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

export async function POST(request) {
  try {
    // TODO: SECURITY - Add rate limiting for registration attempts
    // TODO: SECURITY - Add CAPTCHA or similar anti-bot protection
    // TODO: SECURITY - Implement account enumeration protection
    const { email, password, firstName, lastName, username } = await request.json();

    // Validate required fields
    if (!email || !password) {
      return NextResponse.json(
        { success: false, error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Validate email format
    if (!isValidEmail(email)) {
      return NextResponse.json(
        { success: false, error: 'Invalid email format' },
        { status: 400 }
      );
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return NextResponse.json(
        { 
          success: false, 
          error: 'Password does not meet requirements',
          details: passwordValidation.errors
        },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existingUser = await userDb.findByEmail(email);
    if (existingUser.success && existingUser.data) {
      return NextResponse.json(
        { success: false, error: 'User already exists with this email' },
        { status: 409 }
      );
    }

    // Check if username is already taken (if provided)
    if (username) {
      const existingUsername = await prisma.user.findUnique({
        where: { username }
      });
      
      if (existingUsername) {
        return NextResponse.json(
          { success: false, error: 'Username is already taken' },
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
    const clientIp = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     '127.0.0.1';
    const userAgent = request.headers.get('user-agent') || '';

    await logSecurityEvent({
      userId: userResult.data.id,
      event: 'user_registration',
      details: {
        email: email.toLowerCase(),
        emailSent: emailResult.success
      },
      ipAddress: clientIp,
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
