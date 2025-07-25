/**
 * Device Removal API Route
 * Handles removing specific devices and terminating their sessions
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { sessionDb, prisma } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

export async function DELETE(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const deviceId = searchParams.get('deviceId');
    const sessionId = searchParams.get('sessionId');

    if (!deviceId && !sessionId) {
      return NextResponse.json({
        success: false,
        error: 'Device ID or Session ID is required'
      }, { status: 400 });
    }

    const userId = authResult.data.user.id;

    try {
      await prisma.$transaction(async (tx) => {
        let deletedCount = 0;

        if (deviceId) {
          // Remove trusted device
          const deletedDevice = await tx.trustedDevice.deleteMany({
            where: {
              id: deviceId,
              userId
            }
          });
          deletedCount += deletedDevice.count;

          // Also remove all sessions for this device
          await tx.session.deleteMany({
            where: {
              userId,
              // Note: We'd need to store device fingerprint in sessions to match exactly
              // For now, we'll log this action
            }
          });
        }

        if (sessionId) {
          // Remove specific session
          const deletedSession = await tx.session.deleteMany({
            where: {
              id: sessionId,
              userId
            }
          });
          deletedCount += deletedSession.count;
        }

        if (deletedCount === 0) {
          throw new Error('Device or session not found');
        }
      });

      // Log security event
      await logSecurityEvent({
        userId,
        event: 'device_removed',
        details: {
          deviceId,
          sessionId,
          triggeredBy: 'user',
          method: 'manual_removal'
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      return NextResponse.json({
        success: true,
        message: 'Device removed successfully'
      });

    } catch (dbError) {
      if (dbError.message === 'Device or session not found') {
        return NextResponse.json({
          success: false,
          error: 'Device or session not found'
        }, { status: 404 });
      }
      
      throw dbError;
    }

  } catch (error) {
    console.error('Device removal error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
