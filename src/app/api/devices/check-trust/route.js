/**
 * Device Trust Verification API
 * Handles server-side device fingerprinting and trust management
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { prisma } from '@/lib/database';
import { validateJWT } from '@/lib/auth';
import { checkRateLimit, recordRateLimitAttempt } from '@/lib/rate-limit';
import { getClientIP } from '@/lib/security';
import crypto from 'crypto';

/**
 * Check if a device is trusted for a specific user
 * POST /api/devices/check-trust
 */
export async function POST(request) {
  try {
    // Get client IP for rate limiting
    const clientIP = getClientIP(request);
    
    // Rate limiting
    const rateLimit = checkRateLimit('DEVICE_CHECK_PER_IP', clientIP);
    if (!rateLimit.success) {
      recordRateLimitAttempt('DEVICE_CHECK_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Too many device verification attempts'
      }, { status: 429 });
    }

    // Parse request body
    const { userId, deviceFingerprint } = await request.json();

    if (!userId || !deviceFingerprint) {
      recordRateLimitAttempt('DEVICE_CHECK_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Missing required parameters: userId and deviceFingerprint'
      }, { status: 400 });
    }

    // Validate user session (optional - for authenticated requests)
    const authHeader = request.headers.get('authorization');
    let sessionUserId = null;
    
    if (authHeader) {
      const token = authHeader.replace('Bearer ', '');
      const sessionValidation = await validateJWT(token);
      if (sessionValidation.success) {
        sessionUserId = sessionValidation.data.userId;
      }
    }

    // Security check: ensure user can only check their own devices (if authenticated)
    if (sessionUserId && sessionUserId !== userId) {
      recordRateLimitAttempt('DEVICE_CHECK_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Unauthorized: Cannot check devices for other users'
      }, { status: 403 });
    }

    // Hash the device fingerprint for secure storage
    const deviceHash = crypto.createHash('sha256')
      .update(`${deviceFingerprint}:${userId}`)
      .digest('hex');

    // Check if device exists in database
    let trustedDevice = await prisma.trustedDevice.findFirst({
      where: {
        userId: userId,
        deviceHash: deviceHash
      }
    });

    if (trustedDevice) {
      // Update last seen timestamp
      await prisma.trustedDevice.update({
        where: { id: trustedDevice.id },
        data: {
          lastSeen: new Date(),
          lastIP: clientIP
        }
      });

      recordRateLimitAttempt('DEVICE_CHECK_PER_IP', clientIP);
      
      return NextResponse.json({
        success: true,
        trusted: true,
        deviceId: trustedDevice.id,
        lastSeen: trustedDevice.lastSeen,
        registeredAt: trustedDevice.createdAt
      });
    } else {
      // Device not found - not trusted yet
      recordRateLimitAttempt('DEVICE_CHECK_PER_IP', clientIP);
      
      return NextResponse.json({
        success: true,
        trusted: false,
        message: 'Device not recognized'
      });
    }

  } catch (error) {
    console.error('Device trust check error:', error);
    
    // Record rate limit attempt on error to prevent abuse
    const clientIP = getClientIP(request);
    recordRateLimitAttempt('DEVICE_CHECK_PER_IP', clientIP);
    
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

/**
 * Register a device as trusted
 * PUT /api/devices/check-trust
 */
export async function PUT(request) {
  try {
    // Get client IP for rate limiting
    const clientIP = getClientIP(request);
    
    // Rate limiting for device registration
    const rateLimit = checkRateLimit('DEVICE_REGISTER_PER_IP', clientIP);
    if (!rateLimit.success) {
      recordRateLimitAttempt('DEVICE_REGISTER_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Too many device registration attempts'
      }, { status: 429 });
    }

    // Parse request body
    const { userId, deviceFingerprint, deviceName, metadata } = await request.json();

    if (!userId || !deviceFingerprint) {
      recordRateLimitAttempt('DEVICE_REGISTER_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Missing required parameters: userId and deviceFingerprint'
      }, { status: 400 });
    }

    // Validate user session - device registration requires authentication
    const authHeader = request.headers.get('authorization');
    if (!authHeader) {
      recordRateLimitAttempt('DEVICE_REGISTER_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Authentication required for device registration'
      }, { status: 401 });
    }

    const token = authHeader.replace('Bearer ', '');
    const sessionValidation = await validateJWT(token);
    
    if (!sessionValidation.success || sessionValidation.data.userId !== userId) {
      recordRateLimitAttempt('DEVICE_REGISTER_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Invalid authentication or unauthorized user'
      }, { status: 403 });
    }

    // Hash the device fingerprint for secure storage
    const deviceHash = crypto.createHash('sha256')
      .update(`${deviceFingerprint}:${userId}`)
      .digest('hex');

    // Check if device already exists
    const existingDevice = await prisma.trustedDevice.findFirst({
      where: {
        userId: userId,
        deviceHash: deviceHash
      }
    });

    if (existingDevice) {
      recordRateLimitAttempt('DEVICE_REGISTER_PER_IP', clientIP);
      return NextResponse.json({
        success: true,
        message: 'Device already registered as trusted',
        deviceId: existingDevice.id
      });
    }

    // Register new trusted device
    const trustedDevice = await prisma.trustedDevice.create({
      data: {
        userId: userId,
        deviceHash: deviceHash,
        deviceName: deviceName || 'Unknown Device',
        firstSeen: new Date(),
        lastSeen: new Date(),
        firstIP: clientIP,
        lastIP: clientIP,
        metadata: metadata || {},
        isActive: true
      }
    });

    recordRateLimitAttempt('DEVICE_REGISTER_PER_IP', clientIP);
    
    return NextResponse.json({
      success: true,
      message: 'Device registered as trusted',
      deviceId: trustedDevice.id,
      registeredAt: trustedDevice.createdAt
    });

  } catch (error) {
    console.error('Device registration error:', error);
    
    // Record rate limit attempt on error to prevent abuse
    const clientIP = getClientIP(request);
    recordRateLimitAttempt('DEVICE_REGISTER_PER_IP', clientIP);
    
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

/**
 * Remove device trust (revoke device)
 * DELETE /api/devices/check-trust
 */
export async function DELETE(request) {
  try {
    // Get client IP for rate limiting
    const clientIP = getClientIP(request);
    
    // Rate limiting
    const rateLimit = checkRateLimit('DEVICE_REVOKE_PER_IP', clientIP);
    if (!rateLimit.success) {
      recordRateLimitAttempt('DEVICE_REVOKE_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Too many device revocation attempts'
      }, { status: 429 });
    }

    // Parse request body
    const { userId, deviceId } = await request.json();

    if (!userId || !deviceId) {
      recordRateLimitAttempt('DEVICE_REVOKE_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Missing required parameters: userId and deviceId'
      }, { status: 400 });
    }

    // Validate user session - device revocation requires authentication
    const authHeader = request.headers.get('authorization');
    if (!authHeader) {
      recordRateLimitAttempt('DEVICE_REVOKE_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Authentication required for device revocation'
      }, { status: 401 });
    }

    const token = authHeader.replace('Bearer ', '');
    const sessionValidation = await validateJWT(token);
    
    if (!sessionValidation.success || sessionValidation.data.userId !== userId) {
      recordRateLimitAttempt('DEVICE_REVOKE_PER_IP', clientIP);
      return NextResponse.json({
        success: false,
        error: 'Invalid authentication or unauthorized user'
      }, { status: 403 });
    }

    // Revoke device trust
    const deletedDevice = await prisma.trustedDevice.deleteMany({
      where: {
        id: deviceId,
        userId: userId
      }
    });

    recordRateLimitAttempt('DEVICE_REVOKE_PER_IP', clientIP);
    
    if (deletedDevice.count > 0) {
      return NextResponse.json({
        success: true,
        message: 'Device trust revoked successfully'
      });
    } else {
      return NextResponse.json({
        success: false,
        error: 'Device not found or not owned by user'
      }, { status: 404 });
    }

  } catch (error) {
    console.error('Device revocation error:', error);
    
    // Record rate limit attempt on error to prevent abuse
    const clientIP = getClientIP(request);
    recordRateLimitAttempt('DEVICE_REVOKE_PER_IP', clientIP);
    
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
