/**
 * Email Verification API Route
 * Handles email verification for new user accounts
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { prisma, userDb } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

export async function POST(request) {
  try {
    const { token } = await request.json();

    if (!token) {
      return NextResponse.json(
        { success: false, error: 'Verification token is required' },
        { status: 400 }
      );
    }

    // Find the verification token
    const emailToken = await prisma.emailToken.findUnique({
      where: { token },
      include: { user: true }
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

    // Get client information for logging
    const clientIp = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     '127.0.0.1';
    const userAgent = request.headers.get('user-agent') || '';

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

    // Log security event
    await logSecurityEvent({
      userId: emailToken.userId,
      event: 'email_verified',
      details: {
        email: emailToken.email,
        verificationMethod: 'email_token'
      },
      ipAddress: clientIp,
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
