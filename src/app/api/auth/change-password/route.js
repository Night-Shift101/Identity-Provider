/**
 * Password Change API Route
 * Handles user password updates with security verification
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { userDb } from '@/lib/database';
import { hashPassword, verifyPassword, validatePassword } from '@/lib/auth';
import { logSecurityEvent } from '@/lib/security';

export async function POST(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const { currentPassword, newPassword, confirmPassword } = await request.json();

    // Validate required fields
    if (!currentPassword || !newPassword || !confirmPassword) {
      return NextResponse.json({
        success: false,
        error: 'Current password, new password, and confirmation are required'
      }, { status: 400 });
    }

    // Validate new password confirmation
    if (newPassword !== confirmPassword) {
      return NextResponse.json({
        success: false,
        error: 'New password and confirmation do not match'
      }, { status: 400 });
    }

    // Validate new password strength
    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return NextResponse.json({
        success: false,
        error: passwordValidation.errors.join(', ')
      }, { status: 400 });
    }

    const userId = authResult.data.user.id;

    // Get user with password to verify current password
    const userResult = await userDb.findById(userId);
    if (!userResult.success || !userResult.data) {
      return NextResponse.json({
        success: false,
        error: 'User not found'
      }, { status: 404 });
    }

    const user = userResult.data;

    // Verify current password
    const isCurrentPasswordValid = await verifyPassword(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      // Log failed password change attempt
      await logSecurityEvent({
        userId,
        event: 'password_change_failed',
        details: {
          reason: 'invalid_current_password',
          ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1'
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      return NextResponse.json({
        success: false,
        error: 'Current password is incorrect'
      }, { status: 400 });
    }

    // Check if new password is different from current
    const isSamePassword = await verifyPassword(newPassword, user.password);
    if (isSamePassword) {
      return NextResponse.json({
        success: false,
        error: 'New password must be different from current password'
      }, { status: 400 });
    }

    // Hash new password
    const hashedNewPassword = await hashPassword(newPassword);

    // Update password
    const updateResult = await userDb.updatePassword(userId, hashedNewPassword);
    if (!updateResult.success) {
      return NextResponse.json({
        success: false,
        error: 'Failed to update password'
      }, { status: 500 });
    }

    // Log successful password change
    await logSecurityEvent({
      userId,
      event: 'password_changed',
      details: {
        triggeredBy: 'user',
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1'
      },
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || ''
    });

    return NextResponse.json({
      success: true,
      message: 'Password updated successfully'
    });

  } catch (error) {
    console.error('Password change error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
