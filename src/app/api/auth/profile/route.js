/**
 * Profile API Route
 * Handles user profile retrieval and updates
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { userDb, prisma } from '@/lib/database';
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
        error: authResult.error || 'Unauthorized' 
      }, { status: 401 });
    }

    // Return user profile (already includes safe user data)
    return NextResponse.json({
      success: true,
      error: null,
      data: {
        user: authResult.data.user,
        session: authResult.data.session
      }
    });

  } catch (error) {
    console.error('Profile API error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

export async function PUT(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({ 
        success: false,
        error: authResult.error || 'Unauthorized' 
      }, { status: 401 });
    }

    let requestData;
    try {
      requestData = await request.json();
    } catch (jsonError) {
      console.log('JSON parsing error:', jsonError);
      return NextResponse.json({
        success: false,
        error: 'Invalid JSON data'
      }, { status: 400 });
    }

    const { email, username, firstName, lastName } = requestData;
    const userId = authResult.data.user.id;

    // Debug logging
    console.log('Profile update request data:', { email, username, firstName, lastName, userId });

    // Validate email if provided
    if (email && !isValidEmail(email)) {
      console.log('Email validation failed:', email);
      return NextResponse.json({
        success: false,
        error: 'Invalid email format'
      }, { status: 400 });
    }

    // Validate username if provided and not empty
    if (username && username.trim() && (username.trim().length < 3 || username.trim().length > 30)) {
      console.log('Username validation failed:', username, 'length:', username.trim().length);
      return NextResponse.json({
        success: false,
        error: 'Username must be between 3 and 30 characters'
      }, { status: 400 });
    }

    // Validate names if provided and not empty
    if (firstName && firstName.trim() && firstName.trim().length > 50) {
      return NextResponse.json({
        success: false,
        error: 'First name must be 50 characters or less'
      }, { status: 400 });
    }

    if (lastName && lastName.trim() && lastName.trim().length > 50) {
      return NextResponse.json({
        success: false,
        error: 'Last name must be 50 characters or less'
      }, { status: 400 });
    }

    // Build update object
    const updateData = {};
    let emailChanged = false;
    let newVerificationToken = null;
    
    if (email !== undefined && email !== null) {
      const emailValue = email.toLowerCase().trim();
      if (emailValue) {
        updateData.email = emailValue;
        emailChanged = emailValue !== authResult.data.user.email.toLowerCase();
        
        // If email is changing, reset verification status and prepare verification token
        if (emailChanged) {
          updateData.isVerified = false;
          newVerificationToken = generateSecureToken(32);
        }
      }
    }
    
    if (username !== undefined) {
      const usernameValue = username ? username.trim() : null;
      updateData.username = usernameValue || null;
    }
    
    if (firstName !== undefined) {
      const firstNameValue = firstName ? firstName.trim() : null;
      updateData.firstName = firstNameValue || null;
    }
    
    if (lastName !== undefined) {
      const lastNameValue = lastName ? lastName.trim() : null;
      updateData.lastName = lastNameValue || null;
    }

    console.log('Update data prepared:', updateData);
    console.log('New verification token:', newVerificationToken);

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

    // Create email verification token if email changed
    if (emailChanged && newVerificationToken) {
      try {
        // Create email verification token
        await prisma.emailToken.create({
          data: {
            userId,
            email: updateData.email,
            token: newVerificationToken,
            type: 'EMAIL_VERIFICATION',
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
          }
        });
      } catch (tokenError) {
        console.error('Failed to create email verification token:', tokenError);
        // Continue anyway - user can request new verification later
      }
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
      if (newVerificationToken) {
        try {
          const emailResult = await sendEmailVerification(
            updateData.email,
            newVerificationToken,
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
      error: null,
      message,
      data: {
        user: updateResult.data,
        emailVerificationRequired: emailChanged
      }
    });

  } catch (error) {
    console.error('Profile update error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
