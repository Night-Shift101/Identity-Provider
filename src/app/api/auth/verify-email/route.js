/**
 * Email Verification API Route
 * Handles email verification for new user accounts
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { prisma, userDb } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';
import { checkRateLimit, recordRateLimitAttempt, getClientIPInfo } from '@/lib/rate-limit';
import { ERROR_CODES, createErrorResponse, createSuccessResponse } from '@/lib/error-codes';

export async function POST(request) {
  try {
    // Get client IP with validation
    const clientIPInfo = getClientIPInfo(request);
    const clientIP = clientIPInfo.ip;

    // Rate limiting - Check verification attempts per IP
    const ipRateLimit = checkRateLimit('VERIFICATION_ATTEMPTS_PER_IP', clientIP);
    if (!ipRateLimit.success) {
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.RATE_LIMIT_EXCEEDED, ipRateLimit.error),
        { 
          status: 429,
          headers: {
            'Retry-After': ipRateLimit.data?.retryAfter?.toString() || '900'
          }
        }
      );
    }

    const { token } = await request.json();

    if (!token) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('VERIFICATION_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_MISSING_FIELDS, 'Verification token is required'),
        { status: 400 }
      );
    }

    // Protection against timing attacks - always do the same work
    const startTime = Date.now();
    
    // Find the verification token
    const emailToken = await prisma.emailToken.findUnique({
      where: { token },
      include: { user: true }
    });

    if (!emailToken) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('VERIFICATION_ATTEMPTS_PER_IP', clientIP);
      
      // Timing attack protection - ensure constant response time
      const minDuration = 100; // 100ms minimum
      const elapsed = Date.now() - startTime;
      if (elapsed < minDuration) {
        await new Promise(resolve => setTimeout(resolve, minDuration - elapsed));
      }
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_TOKEN_INVALID, 'Invalid verification token'),
        { status: 400 }
      );
    }

    // Check if token has expired
    if (new Date() > emailToken.expiresAt) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('VERIFICATION_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_TOKEN_EXPIRED, 'Verification token has expired'),
        { status: 400 }
      );
    }

    // Check if token has already been used
    if (emailToken.used) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('VERIFICATION_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_TOKEN_INVALID, 'Verification token has already been used'),
        { status: 400 }
      );
    }

    // Check if token type is correct
    if (emailToken.type !== 'EMAIL_VERIFICATION') {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('VERIFICATION_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_TOKEN_INVALID, 'Invalid token type'),
        { status: 400 }
      );
    }

    // Get client information for logging with validated IP headers
    const userAgent = request.headers.get('user-agent') || '';

    // Log suspicious verification patterns if IP is not trusted
    if (!clientIPInfo.trusted) {
      console.warn('Email verification from untrusted IP:', {
        ip: clientIP,
        source: clientIPInfo.source,
        userAgent: userAgent.substring(0, 100),
        email: emailToken.user.email
      });
    }

    // Update user as verified
    const updateResult = await userDb.update(emailToken.userId, {
      isVerified: true,
      emailVerified: new Date()
    });

    if (!updateResult.success) {
      return NextResponse.json(
        { success: false, error: 'Failed to verify account' },
        { status: 500 }
      );
    }

    // Mark token as used
    await prisma.emailToken.update({
      where: { id: emailToken.id },
      data: { used: true }
    });

    // Log security event with validated IP information
    await logSecurityEvent({
      userId: emailToken.userId,
      event: 'email_verified',
      details: {
        email: emailToken.email,
        verificationMethod: 'email_token',
        ipTrusted: clientIPInfo.trusted,
        ipSource: clientIPInfo.source
      },
      ipAddress: clientIP,
      userAgent
    });

    return NextResponse.json({
      success: true,
      message: 'Email verified successfully',
      data: {
        user: updateResult.data
      }
    }, { status: 200 });

  } catch (error) {
    console.error('Email verification error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const token = searchParams.get('token');

    if (!token) {
      return NextResponse.json(
        { success: false, error: 'Verification token is required' },
        { status: 400 }
      );
    }

    // Find the verification token (just check validity, don't verify yet)
    const emailToken = await prisma.emailToken.findUnique({
      where: { token },
      select: {
        id: true,
        email: true,
        type: true,
        expiresAt: true,
        used: true
      }
    });

    if (!emailToken) {
      return NextResponse.json(
        { success: false, error: 'Invalid verification token' },
        { status: 400 }
      );
    }

    // Check if token has expired
    if (new Date() > emailToken.expiresAt) {
      return NextResponse.json(
        { success: false, error: 'Verification token has expired' },
        { status: 400 }
      );
    }

    // Check if token has already been used
    if (emailToken.used) {
      return NextResponse.json(
        { success: false, error: 'Verification token has already been used' },
        { status: 400 }
      );
    }

    // Check if token type is correct
    if (emailToken.type !== 'EMAIL_VERIFICATION') {
      return NextResponse.json(
        { success: false, error: 'Invalid token type' },
        { status: 400 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Token is valid',
      data: {
        email: emailToken.email,
        canVerify: true
      }
    }, { status: 200 });

  } catch (error) {
    console.error('Email verification check error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
