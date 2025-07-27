/**
 * Secure MFA Verification API
 * Handles TOTP code verification with server-side session management
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { validateMfaSession, incrementMfaAttempts, completeMfaSession } from '@/lib/mfa-sessions';
import { verifyTotpToken, verifyBackupCode } from '@/lib/mfa';
import { checkRateLimit, recordRateLimitAttempt, getClientIP } from '@/lib/rate-limit';
import { logSecurityEvent } from '@/lib/security';
import { sessionDb, userDb } from '@/lib/database';
import { generateSecureToken } from '@/lib/auth';

/**
 * Verify MFA code and complete authentication
 * POST /api/auth/mfa/verify
 */
export async function POST(request) {
  try {
    const ipAddress = getClientIP(request);
    
    // Rate limiting for MFA verification attempts
    const rateLimitResult = checkRateLimit('MFA_VERIFY_PER_IP', ipAddress);
    if (!rateLimitResult.success) {
      return NextResponse.json({
        success: false,
        error: 'Too many verification attempts. Please wait before trying again.',
        data: null
      }, { status: 429 });
    }

    // Get MFA token from secure HTTP-only cookie
    const mfaToken = request.cookies.get('mfa-session')?.value;

    if (!mfaToken) {
      return NextResponse.json({
        success: false,
        error: 'No MFA session found. Please login again.',
        data: null
      }, { status: 401 });
    }

    // Validate MFA session
    const sessionValidation = await validateMfaSession(mfaToken);
    if (!sessionValidation.success) {
      const response = NextResponse.json({
        success: false,
        error: sessionValidation.error,
        data: null
      }, { status: 401 });

      response.cookies.delete('mfa-session');
      return response;
    }

    const { user, sessionId } = sessionValidation.data;

    // Parse request body
    const { code } = await request.json();

    if (!code) {
      return NextResponse.json({
        success: false,
        error: 'Verification code is required',
        data: null
      }, { status: 400 });
    }

    // Clean and validate code format
    const cleanCode = code.replace(/\s/g, '');
    
    // Determine if this is a TOTP code (6 digits) or backup code (8+ characters)
    const isTotpCode = /^\d{6}$/.test(cleanCode);
    const isBackupCode = cleanCode.length >= 8; // Backup codes are typically 8-10 characters
    
    if (!isTotpCode && !isBackupCode) {
      return NextResponse.json({
        success: false,
        error: 'Invalid code format. Please enter a 6-digit TOTP code or a backup code.',
        data: null
      }, { status: 400 });
    }

    // Check if user has MFA enabled
    if (!user.mfaEnabled) {
      await logSecurityEvent({
        userId: user.id,
        event: 'MFA_VERIFICATION_FAILED',
        details: { reason: 'MFA not enabled' },
        ipAddress,
        userAgent: request.headers.get('user-agent')
      });

      return NextResponse.json({
        success: false,
        error: 'MFA is not enabled for this account',
        data: null
      }, { status: 400 });
    }

    let verificationResult;
    let verificationMethod;

    if (isTotpCode) {
      // Verify TOTP code
      if (!user.mfaSecret) {
        await logSecurityEvent({
          userId: user.id,
          event: 'MFA_VERIFICATION_FAILED',
          details: { reason: 'TOTP secret not configured' },
          ipAddress,
          userAgent: request.headers.get('user-agent')
        });

        return NextResponse.json({
          success: false,
          error: 'TOTP is not properly configured for this account',
          data: null
        }, { status: 400 });
      }

      verificationResult = await verifyTotpToken(cleanCode, user.mfaSecret);
      verificationMethod = 'totp';
    } else {
      // Verify backup code
      if (!user.mfaBackupCodes || user.mfaBackupCodes.length === 0) {
        await logSecurityEvent({
          userId: user.id,
          event: 'MFA_VERIFICATION_FAILED',
          details: { reason: 'No backup codes available' },
          ipAddress,
          userAgent: request.headers.get('user-agent')
        });

        return NextResponse.json({
          success: false,
          error: 'No backup codes available for this account',
          data: null
        }, { status: 400 });
      }

      verificationResult = verifyBackupCode(cleanCode, user.mfaBackupCodes);
      verificationMethod = 'backup_code';
    }

    // Increment attempt counter regardless of result
    await incrementMfaAttempts(mfaToken);
    recordRateLimitAttempt('MFA_VERIFY_PER_IP', ipAddress);

    if (!verificationResult.success) {
      await logSecurityEvent({
        userId: user.id,
        event: 'MFA_VERIFICATION_FAILED',
        details: { 
          reason: `Invalid ${verificationMethod} code`,
          method: verificationMethod,
          attempts: sessionValidation.data.attempts + 1
        },
        ipAddress,
        userAgent: request.headers.get('user-agent')
      });

      return NextResponse.json({
        success: false,
        error: 'Invalid verification code. Please try again.',
        data: {
          attemptsRemaining: Math.max(0, sessionValidation.data.maxAttempts - sessionValidation.data.attempts - 1)
        }
      }, { status: 400 });
    }

    // If backup code was used, update the user's backup codes (remove the used one)
    if (verificationMethod === 'backup_code') {
      const updateResult = await userDb.update(user.id, {
        mfaBackupCodes: verificationResult.data.remainingCodes
      });

      if (!updateResult.success) {
        console.error('Failed to update backup codes:', updateResult.error);
        // Continue with authentication despite backup code update failure
      }
    }

    // MFA verification successful - complete the MFA session
    const completionResult = await completeMfaSession(mfaToken);
    if (!completionResult.success) {
      console.error('Failed to complete MFA session:', completionResult.error);
    }

    // Generate session token
    const sessionToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    // Create full authenticated session
    const sessionResult = await sessionDb.create({
      sessionToken,
      userId: user.id,
      expires: expiresAt,
      ipAddress,
      userAgent: request.headers.get('user-agent')
    });

    if (!sessionResult.success) {
      await logSecurityEvent({
        userId: user.id,
        event: 'SESSION_CREATION_FAILED',
        details: { reason: sessionResult.error },
        ipAddress,
        userAgent: request.headers.get('user-agent')
      });

      return NextResponse.json({
        success: false,
        error: 'Failed to create session. Please try again.',
        data: null
      }, { status: 500 });
    }

    // Log successful MFA verification
    await logSecurityEvent({
      userId: user.id,
      event: 'MFA_VERIFICATION_SUCCESS',
      details: { 
        method: verificationMethod,
        sessionId: sessionResult.data.id,
        ...(verificationMethod === 'backup_code' && verificationResult.data.remainingCodes 
          ? { remainingBackupCodes: verificationResult.data.remainingCodes.length }
          : {})
      },
      ipAddress,
      userAgent: request.headers.get('user-agent')
    });

    // Create response with session cookie
    const response = NextResponse.json({
      success: true,
      error: null,
      data: {
        message: 'MFA verification successful',
        user: {
          id: user.id,
          email: user.email,
          username: user.username
        }
      }
    });

    // Set secure session cookie
    response.cookies.set('session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 // 30 days
    });

    // Clear MFA session cookie
    response.cookies.delete('mfa-session');

    return response;

  } catch (error) {
    console.error('MFA verification error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error',
      data: null
    }, { status: 500 });
  }
}
