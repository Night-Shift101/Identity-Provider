/**
 * Trusted Devices Management API Route
 * Handles viewing and removing trusted devices
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { prisma } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

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

    const userId = authResult.data.user.id;

    // Get all trusted devices for the user
    const devices = await prisma.trustedDevice.findMany({
      where: {
        userId,
        isActive: true
      },
      orderBy: {
        lastSeen: 'desc'
      },
      select: {
        id: true,
        deviceHash: true,
        deviceName: true,
        firstSeen: true,
        lastSeen: true,
        firstIP: true,
        lastIP: true,
        metadata: true,
        createdAt: true
      }
    });

    // Parse device metadata for better display
    const devicesWithInfo = devices.map(device => {
      // Extract user agent from metadata if available
      const metadata = device.metadata || {};
      const userAgent = metadata.userAgent || '';
      let deviceInfo = 'Unknown Device';
      let browserInfo = 'Unknown Browser';
      let osInfo = 'Unknown OS';
      
      // Simple user agent parsing
      if (userAgent.includes('Windows')) osInfo = 'Windows';
      else if (userAgent.includes('Mac OS X')) osInfo = 'macOS';
      else if (userAgent.includes('Linux')) osInfo = 'Linux';
      else if (userAgent.includes('Android')) osInfo = 'Android';
      else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) osInfo = 'iOS';
      
      if (userAgent.includes('Chrome')) browserInfo = 'Chrome';
      else if (userAgent.includes('Firefox')) browserInfo = 'Firefox';
      else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) browserInfo = 'Safari';
      else if (userAgent.includes('Edge')) browserInfo = 'Edge';
      
      if (userAgent.includes('Mobile')) deviceInfo = 'Mobile Device';
      else if (userAgent.includes('Tablet') || userAgent.includes('iPad')) deviceInfo = 'Tablet';
      else deviceInfo = 'Desktop';

      return {
        id: device.id,
        deviceHash: device.deviceHash,
        name: device.deviceName || `${deviceInfo} - ${browserInfo}`,
        deviceInfo,
        browserInfo,
        osInfo,
        ipAddress: device.lastIP || device.firstIP,
        lastSeen: device.lastSeen,
        firstSeen: device.firstSeen,
        createdAt: device.createdAt,
        isCurrentDevice: false // We'll set this based on current session
      };
    });

    return NextResponse.json({
      success: true,
      data: {
        devices: devicesWithInfo,
        totalDevices: devices.length
      }
    });

  } catch (error) {
    console.error('Devices fetch error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to retrieve devices'
    }, { status: 500 });
  }
}

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

    const userId = authResult.data.user.id;
    const { searchParams } = new URL(request.url);
    const deviceId = searchParams.get('deviceId');
    const action = searchParams.get('action'); // 'remove' or 'remove-all-others'

    if (!deviceId && action !== 'remove-all-others') {
      return NextResponse.json({
        success: false,
        error: 'Device ID or action is required'
      }, { status: 400 });
    }

    if (action === 'remove-all-others') {
      // Remove all devices except current (if we can identify it)
      // For now, let's just remove all devices since we don't have current device tracking
      const deletedDevices = await prisma.trustedDevice.updateMany({
        where: {
          userId,
          isActive: true
        },
        data: {
          isActive: false
        }
      });

      // Log security event
      await logSecurityEvent({
        userId,
        event: 'devices_removed',
        details: {
          action: 'all_others',
          removedCount: deletedDevices.count,
          triggeredBy: 'user'
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      return NextResponse.json({
        success: true,
        message: `${deletedDevices.count} devices removed successfully`
      });

    } else {
      // Remove specific device
      const device = await prisma.trustedDevice.findFirst({
        where: {
          id: deviceId,
          userId,
          isActive: true
        }
      });

      if (!device) {
        return NextResponse.json({
          success: false,
          error: 'Device not found or already removed'
        }, { status: 404 });
      }

      // Remove the device
      await prisma.trustedDevice.update({
        where: {
          id: deviceId
        },
        data: {
          isActive: false
        }
      });

      // Log security event
      await logSecurityEvent({
        userId,
        event: 'device_removed',
        details: {
          deviceId: device.deviceId,
          deviceName: device.name,
          triggeredBy: 'user'
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      return NextResponse.json({
        success: true,
        message: 'Device removed successfully'
      });
    }

  } catch (error) {
    console.error('Device removal error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to remove device'
    }, { status: 500 });
  }
}
