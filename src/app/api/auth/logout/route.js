/**
 * User Logout API Route
 * Handles user session termination and device management
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { sessionDb } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

export async function POST(request) {
  try {
    // Parse JSON body safely
    let logoutAll = false;
    try {
      const body = await request.json();
      logoutAll = body.logoutAll || false;
    } catch (e) {
      // No JSON body or invalid JSON - use default values
      logoutAll = false;
    }
    
    // Get session token from cookie or Authorization header
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'No active session found' },
        { status: 401 }
      );
    }

    // Get client information for logging
    const clientIp = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     '127.0.0.1';
    const userAgent = request.headers.get('user-agent') || '';

    // Find current session
    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid session' },
        { status: 401 }
      );
    }

    const session = sessionResult.data;
    const userId = session.userId;

    if (logoutAll) {
      // Logout from all devices
      const deleteAllResult = await sessionDb.deleteAllForUser(userId);
      if (!deleteAllResult.success) {
        return NextResponse.json(
          { success: false, error: 'Failed to logout from all devices' },
          { status: 500 }
        );
      }

      // Log security event
      await logSecurityEvent({
        userId,
        event: 'logout_all_devices',
        details: {
          sessionCount: 'all',
          triggeredBy: 'user'
        },
        ipAddress: clientIp,
        userAgent
      });

      // Prepare response
      const response = NextResponse.json({
        success: true,
        message: 'Logged out from all devices successfully'
      }, { status: 200 });

      // Clear session cookie
      response.cookies.set('session', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 0
      });

      return response;
    } else {
      // Logout from current device only
      const deleteResult = await sessionDb.delete(sessionToken);
      if (!deleteResult.success) {
        return NextResponse.json(
          { success: false, error: 'Failed to logout' },
          { status: 500 }
        );
      }

      // Log security event
      await logSecurityEvent({
        userId,
        event: 'logout',
        details: {
          sessionId: session.id,
          triggeredBy: 'user'
        },
        ipAddress: clientIp,
        userAgent
      });

      // Prepare response
      const response = NextResponse.json({
        success: true,
        message: 'Logged out successfully'
      }, { status: 200 });

      // Clear session cookie
      response.cookies.set('session', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 0
      });

      return response;
    }

  } catch (error) {
    console.error('Logout error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
