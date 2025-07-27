/**
 * Secure MFA Verification API
 * Handles TOTP code verification with server-side session management
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { validateMfaSession, incrementMfaAttempts, completeMfaSession } from '@/lib/mfa-sessions';
import { verifyTotpToken } from '@/lib/mfa';
import { createSession } from '@/lib/auth-helpers';
import { getClientIpAddress } from '@/lib/security';
import { checkRateLimit, recordRateLimitAttempt } from '@/lib/rate-limit';
import { logSecurityEvent } from '@/lib/security';

/**
 * Verify MFA code and complete authentication
 * POST /api/auth/mfa/verify
 */
export async function POST(request) {
  try {
    const ipAddress = getClientIpAddress(request);
    
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
    if (!/^\d{6}$/.test(cleanCode)) {
      return NextResponse.json({
        success: false,
        error: 'Invalid code format. Please enter a 6-digit number.',
        data: null
      }, { status: 400 });
    }

    // Check if user has MFA enabled and TOTP secret
    if (!user.mfaEnabled || !user.totpSecret) {
      await logSecurityEvent({
        userId: user.id,
        event: 'MFA_VERIFICATION_FAILED',
        details: { reason: 'MFA not properly configured' },
        ipAddress,
        userAgent: request.headers.get('user-agent')
      });

      return NextResponse.json({
        success: false,
        error: 'MFA is not properly configured for this account',
        data: null
      }, { status: 400 });
    }

    // Verify TOTP code
    const verificationResult = await verifyTotpToken(cleanCode, user.totpSecret);

    // Increment attempt counter regardless of result
    await incrementMfaAttempts(mfaToken);
    recordRateLimitAttempt('MFA_VERIFY_PER_IP', ipAddress);

    if (!verificationResult.success) {
      await logSecurityEvent({
        userId: user.id,
        event: 'MFA_VERIFICATION_FAILED',
        details: { 
          reason: 'Invalid TOTP code',
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

    // MFA verification successful - complete the MFA session
    const completionResult = await completeMfaSession(mfaToken);
    if (!completionResult.success) {
      console.error('Failed to complete MFA session:', completionResult.error);
    }

    // Create full authenticated session
    const sessionResult = await createSession(
      user.id,
      request.headers.get('user-agent'),
      ipAddress
    );

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
        method: 'totp',
        sessionId: sessionResult.data.sessionId
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
    response.cookies.set('session', sessionResult.data.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60, // 7 days
      path: '/'
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
