/**
 * User Registration API Route
 * Handles new user account creation with email verification
 * @author IdP System
 */

// TODO: FUNCTIONALITY - Implement API versioning for backward compatibility
import { NextResponse } from 'next/server';
import { hashPassword, isValidEmail, validatePassword, generateSecureToken } from '@/lib/auth';
import { userDb, prisma } from '@/lib/database';
import { sendEmailVerification } from '@/lib/email';
import { logSecurityEvent } from '@/lib/security';
import { checkRateLimit, recordRateLimitAttempt, getClientIPInfo } from '@/lib/rate-limit';
import { ERROR_CODES, createErrorResponse, createSuccessResponse } from '@/lib/error-codes';

export async function POST(request) {
  try {
    // Get client IP with validation
    const clientIPInfo = getClientIPInfo(request);
    const clientIP = clientIPInfo.ip;

    // Rate limiting - Check registration attempts per IP
    const ipRateLimit = checkRateLimit('REGISTRATION_ATTEMPTS_PER_IP', clientIP);
    if (!ipRateLimit.success) {
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.RATE_LIMIT_EXCEEDED, ipRateLimit.error),
        { 
          status: 429,
          headers: {
            'Retry-After': ipRateLimit.data?.retryAfter?.toString() || '3600'
          }
        }
      );
    }

    const { email, password, firstName, lastName, username } = await request.json();

    // Validate required fields
    if (!email || !password) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('REGISTRATION_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_MISSING_FIELDS),
        { status: 400 }
      );
    }

    // Validate email format
    if (!isValidEmail(email)) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('REGISTRATION_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_INVALID_EMAIL),
        { status: 400 }
      );
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('REGISTRATION_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_INVALID_PASSWORD, 
          'Password does not meet requirements', 
          { details: passwordValidation.errors }),
        { status: 400 }
      );
    }

    // Check if user already exists (account enumeration protection)
    const existingUser = await userDb.findByEmail(email);
    if (existingUser.success && existingUser.data) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('REGISTRATION_ATTEMPTS_PER_IP', clientIP);
      
      // Don't reveal that user exists (account enumeration protection)
      return NextResponse.json(
        createSuccessResponse('Registration successful. Please check your email to verify your account.'),
        { status: 200 }
      );
    }

    // Check if username is already taken (if provided)
    if (username) {
      const existingUsername = await prisma.user.findUnique({
        where: { username }
      });
      
      if (existingUsername) {
        // Record failed attempt for rate limiting
        recordRateLimitAttempt('REGISTRATION_ATTEMPTS_PER_IP', clientIP);
        
        return NextResponse.json(
          createErrorResponse(ERROR_CODES.VALIDATION_MISSING_FIELDS, 'Username is already taken'),
          { status: 409 }
        );
      }
    }

    // Hash password
    const hashResult = await hashPassword(password);
    if (!hashResult.success) {
      return NextResponse.json(
        { success: false, error: 'Password processing failed' },
        { status: 500 }
      );
    }

    // Create user
    const userResult = await userDb.create({
      email: email.toLowerCase(),
      password: hashResult.data,
      firstName: firstName || null,
      lastName: lastName || null,
      username: username || null,
      isVerified: false
    });

    if (!userResult.success) {
      return NextResponse.json(
        { success: false, error: userResult.error },
        { status: 500 }
      );
    }

    // Generate email verification token
    const verificationToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store verification token
    await prisma.emailToken.create({
      data: {
        email: email.toLowerCase(),
        token: verificationToken,
        type: 'EMAIL_VERIFICATION',
        expiresAt,
        userId: userResult.data.id
      }
    });

    // Send verification email
    const emailResult = await sendEmailVerification(
      email,
      verificationToken,
      firstName
    );

    // Log security event
    // Log security event with validated IP
    const userAgent = request.headers.get('user-agent') || '';

    await logSecurityEvent({
      userId: userResult.data.id,
      event: 'user_registration',
      details: {
        email: email.toLowerCase(),
        emailSent: emailResult.success,
        ipTrusted: clientIPInfo.trusted,
        ipSource: clientIPInfo.source
      },
      ipAddress: clientIP,
      userAgent
    });

    return NextResponse.json({
      success: true,
      message: 'Account created successfully. Please check your email to verify your account.',
      data: {
        user: userResult.data,
        emailSent: emailResult.success
      }
    }, { status: 201 });

  } catch (error) {
    console.error('Registration error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
