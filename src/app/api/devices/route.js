/**
 * Device Management API Routes
 * Handles trusted device management and monitoring
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { sessionDb, prisma } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

export async function GET(request) {
  try {
    // Get authenticated user
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      );
    }

    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid session' },
        { status: 401 }
      );
    }

    const user = sessionResult.data.user;
    
    // Get user's trusted devices
    const trustedDevices = await prisma.trustedDevice.findMany({
      where: {
        userId: user.id,
        isActive: true
      },
      select: {
        id: true,
        deviceId: true,
        name: true,
        userAgent: true,
        ipAddress: true,
        lastSeen: true,
        createdAt: true
      },
      orderBy: { lastSeen: 'desc' }
    });

    // Get user's active sessions
    const activeSessions = await prisma.session.findMany({
      where: {
        userId: user.id,
        expires: {
          gt: new Date()
        }
      },
      select: {
        id: true,
        ipAddress: true,
        userAgent: true,
        expires: true
      },
      orderBy: { expires: 'desc' }
    });

    return NextResponse.json({
      success: true,
      data: {
        trustedDevices,
        activeSessions,
        currentSession: {
          id: sessionResult.data.id,
          ipAddress: sessionResult.data.ipAddress,
          userAgent: sessionResult.data.userAgent
        }
      }
    }, { status: 200 });

  } catch (error) {
    console.error('Device management error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function DELETE(request) {
  try {
    const { deviceId, sessionId, action } = await request.json();
    
    // Get authenticated user
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      );
    }

    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid session' },
        { status: 401 }
      );
    }

    const user = sessionResult.data.user;
    const clientIp = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     '127.0.0.1';
    const userAgent = request.headers.get('user-agent') || '';

    switch (action) {
      case 'remove-trusted-device':
        if (!deviceId) {
          return NextResponse.json(
            { success: false, error: 'Device ID is required' },
            { status: 400 }
          );
        }

        const removeResult = await removeTrustedDevice(user.id, deviceId);
        if (!removeResult.success) {
          return NextResponse.json(
            { success: false, error: removeResult.error },
            { status: 500 }
          );
        }

        await logSecurityEvent({
          userId: user.id,
          event: 'trusted_device_removed',
          details: { deviceId },
          ipAddress: clientIp,
          userAgent
        });

        return NextResponse.json({
          success: true,
          message: 'Trusted device removed successfully'
        }, { status: 200 });

      case 'terminate-session':
        if (!sessionId) {
          return NextResponse.json(
            { success: false, error: 'Session ID is required' },
            { status: 400 }
          );
        }

        // Don't allow terminating current session
        if (sessionId === sessionResult.data.id) {
          return NextResponse.json(
            { success: false, error: 'Cannot terminate current session' },
            { status: 400 }
          );
        }

        // Find and delete the specific session
        const targetSession = await prisma.session.findFirst({
          where: {
            id: sessionId,
            userId: user.id
          }
        });

        if (!targetSession) {
          return NextResponse.json(
            { success: false, error: 'Session not found' },
            { status: 404 }
          );
        }

        await prisma.session.delete({
          where: { id: sessionId }
        });

        await logSecurityEvent({
          userId: user.id,
          event: 'session_terminated',
          details: { 
            sessionId,
            terminatedFrom: clientIp
          },
          ipAddress: clientIp,
          userAgent
        });

        return NextResponse.json({
          success: true,
          message: 'Session terminated successfully'
        }, { status: 200 });

      case 'terminate-all-sessions':
        // Get count of sessions that will be terminated (excluding current)
        const sessionsToTerminate = await prisma.session.count({
          where: {
            userId: user.id,
            id: {
              not: sessionResult.data.id
            }
          }
        });

        // Delete all other sessions
        await prisma.session.deleteMany({
          where: {
            userId: user.id,
            id: {
              not: sessionResult.data.id
            }
          }
        });

        await logSecurityEvent({
          userId: user.id,
          event: 'all_sessions_terminated',
          details: { 
            sessionCount: sessionsToTerminate,
            terminatedFrom: clientIp
          },
          ipAddress: clientIp,
          userAgent
        });

        return NextResponse.json({
          success: true,
          message: `${sessionsToTerminate} sessions terminated successfully`
        }, { status: 200 });

      case 'remove-all-trusted-devices':
        // Get count of devices that will be removed
        const devicesToRemove = await prisma.trustedDevice.count({
          where: {
            userId: user.id,
            isActive: true
          }
        });

        // Deactivate all trusted devices
        await prisma.trustedDevice.updateMany({
          where: {
            userId: user.id,
            isActive: true
          },
          data: {
            isActive: false
          }
        });

        await logSecurityEvent({
          userId: user.id,
          event: 'all_trusted_devices_removed',
          details: { 
            deviceCount: devicesToRemove
          },
          ipAddress: clientIp,
          userAgent
        });

        return NextResponse.json({
          success: true,
          message: `${devicesToRemove} trusted devices removed successfully`
        }, { status: 200 });

      default:
        return NextResponse.json(
          { success: false, error: 'Invalid action' },
          { status: 400 }
        );
    }

  } catch (error) {
    console.error('Device deletion error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function PATCH(request) {
  try {
    const { deviceId, name } = await request.json();
    
    if (!deviceId || !name) {
      return NextResponse.json(
        { success: false, error: 'Device ID and name are required' },
        { status: 400 }
      );
    }

    // Get authenticated user
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      );
    }

    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid session' },
        { status: 401 }
      );
    }

    const user = sessionResult.data.user;

    // Update device name
    const updateResult = await prisma.trustedDevice.updateMany({
      where: {
        deviceId,
        userId: user.id,
        isActive: true
      },
      data: {
        name: name.trim()
      }
    });

    if (updateResult.count === 0) {
      return NextResponse.json(
        { success: false, error: 'Device not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Device name updated successfully'
    }, { status: 200 });

  } catch (error) {
    console.error('Device update error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
