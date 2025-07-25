/**
 * Account Deletion API Route
 * Handles permanent account deletion with confirmation
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { userDb, sessionDb, prisma } from '@/lib/database';
import { verifyPassword } from '@/lib/auth';
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

    const { password, confirmDeletion } = await request.json();

    // Validate required fields
    if (!password || confirmDeletion !== 'DELETE_MY_ACCOUNT') {
      return NextResponse.json({
        success: false,
        error: 'Password and deletion confirmation are required. Type "DELETE_MY_ACCOUNT" to confirm.'
      }, { status: 400 });
    }

    const userId = authResult.data.user.id;

    // Get user with password to verify
    const userResult = await userDb.findById(userId);
    if (!userResult.success || !userResult.data) {
      return NextResponse.json({
        success: false,
        error: 'User not found'
      }, { status: 404 });
    }

    const user = userResult.data;

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
      // Log failed deletion attempt
      await logSecurityEvent({
        userId,
        event: 'account_deletion_failed',
        details: {
          reason: 'invalid_password',
          ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1'
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      return NextResponse.json({
        success: false,
        error: 'Password is incorrect'
      }, { status: 400 });
    }

    // Log account deletion
    await logSecurityEvent({
      userId,
      event: 'account_deleted',
      details: {
        email: user.email,
        deletedAt: new Date().toISOString(),
        triggeredBy: 'user'
      },
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || ''
    });

    // Delete user and all related data (cascade delete should handle most)
    try {
      await prisma.$transaction(async (tx) => {
        // Delete in order to respect foreign key constraints
        await tx.emailToken.deleteMany({ where: { userId } });
        await tx.securityLog.deleteMany({ where: { userId } });
        await tx.loginActivity.deleteMany({ where: { userId } });
        await tx.session.deleteMany({ where: { userId } });
        await tx.trustedDevice.deleteMany({ where: { userId } });
        await tx.webAuthnCredential.deleteMany({ where: { userId } });
        await tx.oAuthAccount.deleteMany({ where: { userId } });
        
        // Finally delete the user
        await tx.user.delete({ where: { id: userId } });
      });
    } catch (dbError) {
      console.error('Database deletion error:', dbError);
      return NextResponse.json({
        success: false,
        error: 'Failed to delete account data'
      }, { status: 500 });
    }

    // Clear session cookie
    const response = NextResponse.json({
      success: true,
      message: 'Account permanently deleted'
    });

    response.cookies.set('session', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0
    });

    return response;

  } catch (error) {
    console.error('Account deletion error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
