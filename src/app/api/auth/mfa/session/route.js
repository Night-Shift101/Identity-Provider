/**
 * Secure MFA Session API
 * Handles server-side MFA session management
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { 
  createMfaSession, 
  validateMfaSession, 
  incrementMfaAttempts, 
  completeMfaSession 
} from '@/lib/mfa-sessions';
import { getClientIpAddress } from '@/lib/security';
import { checkRateLimit, recordRateLimitAttempt } from '@/lib/rate-limit';

/**
 * Create MFA session
 * POST /api/auth/mfa/session
 */
export async function POST(request) {
  try {
    const ipAddress = getClientIpAddress(request);
    
    // Rate limiting for MFA session creation
    const rateLimitResult = checkRateLimit('MFA_SESSION_CREATE_PER_IP', ipAddress);
    if (!rateLimitResult.success) {
      return NextResponse.json({
        success: false,
        error: 'Too many MFA session requests. Please wait before trying again.',
        data: null
      }, { status: 429 });
    }

    const { userId, userAgent } = await request.json();

    if (!userId) {
      return NextResponse.json({
        success: false,
        error: 'User ID is required',
        data: null
      }, { status: 400 });
    }

    // Create secure MFA session
    const sessionResult = await createMfaSession(
      userId, 
      userAgent || request.headers.get('user-agent'),
      ipAddress
    );

    if (!sessionResult.success) {
      recordRateLimitAttempt('MFA_SESSION_CREATE_PER_IP', ipAddress);
      return NextResponse.json({
        success: false,
        error: sessionResult.error,
        data: null
      }, { status: 500 });
    }

    // Record successful rate limit attempt
    recordRateLimitAttempt('MFA_SESSION_CREATE_PER_IP', ipAddress);

    // Set secure HTTP-only cookie for MFA session
    const response = NextResponse.json({
      success: true,
      error: null,
      data: {
        sessionId: sessionResult.data.sessionId,
        expiresAt: sessionResult.data.expiresAt
      }
    });

    // Set HTTP-only cookie with the MFA token (secure server-side storage)
    response.cookies.set('mfa-session', sessionResult.data.mfaToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 10 * 60, // 10 minutes
      path: '/auth/mfa'
    });

    return response;

  } catch (error) {
    console.error('MFA session creation error:', error);
    recordRateLimitAttempt('MFA_SESSION_CREATE_PER_IP', getClientIpAddress(request));
    return NextResponse.json({
      success: false,
      error: 'Internal server error',
      data: null
    }, { status: 500 });
  }
}

/**
 * Validate MFA session
 * GET /api/auth/mfa/session
 */
export async function GET(request) {
  try {
    const ipAddress = getClientIpAddress(request);
    
    // Rate limiting for MFA session validation
    const rateLimitResult = checkRateLimit('MFA_SESSION_VALIDATE_PER_IP', ipAddress);
    if (!rateLimitResult.success) {
      return NextResponse.json({
        success: false,
        error: 'Too many validation requests. Please wait before trying again.',
        data: null
      }, { status: 429 });
    }

    // Get MFA token from secure HTTP-only cookie
    const mfaToken = request.cookies.get('mfa-session')?.value;

    if (!mfaToken) {
      return NextResponse.json({
        success: false,
        error: 'No MFA session found',
        data: null
      }, { status: 401 });
    }

    // Validate MFA session
    const validationResult = await validateMfaSession(mfaToken);

    if (!validationResult.success) {
      // Clear invalid cookie
      const response = NextResponse.json({
        success: false,
        error: validationResult.error,
        data: null
      }, { status: 401 });

      response.cookies.delete('mfa-session');
      recordRateLimitAttempt('MFA_SESSION_VALIDATE_PER_IP', ipAddress);
      return response;
    }

    // Record successful rate limit attempt
    recordRateLimitAttempt('MFA_SESSION_VALIDATE_PER_IP', ipAddress);

    return NextResponse.json({
      success: true,
      error: null,
      data: {
        sessionId: validationResult.data.sessionId,
        userId: validationResult.data.userId,
        attempts: validationResult.data.attempts,
        maxAttempts: validationResult.data.maxAttempts,
        expiresAt: validationResult.data.expiresAt,
        user: {
          email: validationResult.data.user.email,
          mfaEnabled: validationResult.data.user.mfaEnabled
        }
      }
    });

  } catch (error) {
    console.error('MFA session validation error:', error);
    recordRateLimitAttempt('MFA_SESSION_VALIDATE_PER_IP', getClientIpAddress(request));
    return NextResponse.json({
      success: false,
      error: 'Internal server error',
      data: null
    }, { status: 500 });
  }
}

/**
 * Complete MFA session (after successful verification)
 * DELETE /api/auth/mfa/session
 */
export async function DELETE(request) {
  try {
    const ipAddress = getClientIpAddress(request);
    
    // Rate limiting
    const rateLimitResult = checkRateLimit('MFA_SESSION_COMPLETE_PER_IP', ipAddress);
    if (!rateLimitResult.success) {
      return NextResponse.json({
        success: false,
        error: 'Too many completion requests. Please wait before trying again.',
        data: null
      }, { status: 429 });
    }

    // Get MFA token from secure HTTP-only cookie
    const mfaToken = request.cookies.get('mfa-session')?.value;

    if (!mfaToken) {
      return NextResponse.json({
        success: false,
        error: 'No MFA session found',
        data: null
      }, { status: 401 });
    }

    // Complete MFA session
    const completionResult = await completeMfaSession(mfaToken);

    if (!completionResult.success) {
      recordRateLimitAttempt('MFA_SESSION_COMPLETE_PER_IP', ipAddress);
      return NextResponse.json({
        success: false,
        error: completionResult.error,
        data: null
      }, { status: 400 });
    }

    // Record successful rate limit attempt
    recordRateLimitAttempt('MFA_SESSION_COMPLETE_PER_IP', ipAddress);

    // Clear MFA session cookie
    const response = NextResponse.json({
      success: true,
      error: null,
      data: {
        sessionCompleted: true
      }
    });

    response.cookies.delete('mfa-session');
    return response;

  } catch (error) {
    console.error('MFA session completion error:', error);
    recordRateLimitAttempt('MFA_SESSION_COMPLETE_PER_IP', getClientIpAddress(request));
    return NextResponse.json({
      success: false,
      error: 'Internal server error',
      data: null
    }, { status: 500 });
  }
}
