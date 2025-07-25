/**
 * Resend Email Verification API Route
 * Handles resending email verification tokens for authenticated users
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { prisma } from '@/lib/database';
import { generateSecureToken } from '@/lib/auth';
import { sendEmailVerification } from '@/lib/email';

export async function POST(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({ 
        success: false,
        error: authResult.error || 'Unauthorized' 
      }, { status: 401 });
    }

    const user = authResult.data.user;

    // Check if already verified
    if (user.isVerified) {
      return NextResponse.json({
        success: false,
        error: 'Email is already verified'
      }, { status: 400 });
    }

    // Generate new verification token
    const newToken = generateSecureToken(32);
    
    // Create or update email verification token
    try {
      // Delete any existing email verification tokens for this user
      await prisma.emailToken.deleteMany({
        where: {
          userId: user.id,
          type: 'EMAIL_VERIFICATION'
        }
      });

      // Create new email verification token
      await prisma.emailToken.create({
        data: {
          userId: user.id,
          email: user.email,
          token: newToken,
          type: 'EMAIL_VERIFICATION',
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
        }
      });
    } catch (tokenError) {
      console.error('Failed to create email verification token:', tokenError);
      return NextResponse.json({
        success: false,
        error: 'Failed to generate verification token'
      }, { status: 500 });
    }

    // Send verification email
    try {
      const emailResult = await sendEmailVerification(
        user.email,
        newToken,
        user.firstName
      );
      
      if (!emailResult.success) {
        console.error('Failed to send verification email:', emailResult.error);
        return NextResponse.json({
          success: false,
          error: 'Failed to send verification email'
        }, { status: 500 });
      }
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      return NextResponse.json({
        success: false,
        error: 'Failed to send verification email'
      }, { status: 500 });
    }

    return NextResponse.json({
      success: true,
      message: 'Verification email sent successfully'
    });

  } catch (error) {
    console.error('Resend verification error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
