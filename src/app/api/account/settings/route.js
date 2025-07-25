/**
 * Account Settings API Route
 * Handles user profile updates and preferences
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { userDb } from '@/lib/database';
import { isValidEmail, generateSecureToken } from '@/lib/auth';
import { logSecurityEvent } from '@/lib/security';
import { sendEmailVerification } from '@/lib/email';

export async function GET(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    // Return user settings (safe data only)
    const user = authResult.data.user;
    return NextResponse.json({
      success: true,
      data: {
        profile: {
          id: user.id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          isVerified: user.isVerified,
          mfaEnabled: user.mfaEnabled,
          createdAt: user.createdAt
        }
      }
    });

  } catch (error) {
    console.error('Account settings fetch error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

export async function PATCH(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const { email, username, firstName, lastName } = await request.json();
    const userId = authResult.data.user.id;

    // Validate email if provided
    if (email && !isValidEmail(email)) {
      return NextResponse.json({
        success: false,
        error: 'Invalid email format'
      }, { status: 400 });
    }

    // Validate username if provided
    if (username && (username.length < 3 || username.length > 30)) {
      return NextResponse.json({
        success: false,
        error: 'Username must be between 3 and 30 characters'
      }, { status: 400 });
    }

    // Validate names if provided
    if (firstName && firstName.length > 50) {
      return NextResponse.json({
        success: false,
        error: 'First name must be 50 characters or less'
      }, { status: 400 });
    }

    if (lastName && lastName.length > 50) {
      return NextResponse.json({
        success: false,
        error: 'Last name must be 50 characters or less'
      }, { status: 400 });
    }

    // Build update object
    const updateData = {};
    let emailChanged = false;
    
    if (email !== undefined) {
      updateData.email = email.toLowerCase();
      emailChanged = email.toLowerCase() !== authResult.data.user.email.toLowerCase();
      
      // If email is changing, reset verification status and generate new token
      if (emailChanged) {
        updateData.isVerified = false;
        updateData.verificationToken = generateSecureToken(32);
      }
    }
    
    if (username !== undefined) updateData.username = username.trim() || null;
    if (firstName !== undefined) updateData.firstName = firstName.trim() || null;
    if (lastName !== undefined) updateData.lastName = lastName.trim() || null;

    // Update user
    const updateResult = await userDb.update(userId, updateData);
    if (!updateResult.success) {
      // Check for unique constraint violations
      if (updateResult.error?.includes('email')) {
        return NextResponse.json({
          success: false,
          error: 'Email is already in use'
        }, { status: 400 });
      }
      
      if (updateResult.error?.includes('username')) {
        return NextResponse.json({
          success: false,
          error: 'Username is already taken'
        }, { status: 400 });
      }

      return NextResponse.json({
        success: false,
        error: 'Failed to update profile'
      }, { status: 500 });
    }

    // Log security event for email changes
    if (emailChanged) {
      await logSecurityEvent({
        userId,
        event: 'email_changed',
        details: {
          oldEmail: authResult.data.user.email,
          newEmail: updateData.email,
          requiresVerification: true
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      // Send new email verification
      try {
        const emailResult = await sendEmailVerification(
          updateData.email,
          updateData.verificationToken,
          updateData.firstName || authResult.data.user.firstName
        );
        
        if (!emailResult.success) {
          console.error('Failed to send verification email:', emailResult.error);
          // Continue anyway - user can resend verification later
        }
      } catch (emailError) {
        console.error('Email sending error:', emailError);
        // Continue anyway - user can resend verification later
      }
    }

    // Log profile update
    await logSecurityEvent({
      userId,
      event: 'profile_updated',
      details: {
        updatedFields: Object.keys(updateData),
        triggeredBy: 'user'
      },
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || ''
    });

    // Prepare response message
    let message = 'Profile updated successfully';
    if (emailChanged) {
      message = 'Profile updated successfully. Please check your new email address for a verification link.';
    }

    return NextResponse.json({
      success: true,
      message,
      data: {
        user: updateResult.data,
        emailVerificationRequired: emailChanged
      }
    });

  } catch (error) {
    console.error('Account settings update error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
