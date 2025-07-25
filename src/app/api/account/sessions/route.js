/**
 * Session Management API Route
 * Handles active session viewing and management
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { sessionDb, prisma } from '@/lib/database';
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
    const currentSessionId = authResult.data.session.id;

    // Get all user sessions
    const sessions = await prisma.session.findMany({
      where: {
        userId: userId
      },
      orderBy: {
        expires: 'desc'
      },
      select: {
        id: true,
        sessionToken: true,
        expires: true,
        ipAddress: true,
        userAgent: true
      }
    });    // Parse user agents for better display
    const sessionsWithInfo = sessions.map(session => {
      const isCurrentSession = session.id === currentSessionId;
      
      // Simple user agent parsing (you might want to use a library like ua-parser-js)
      const userAgent = session.userAgent || '';
      let deviceInfo = 'Unknown Device';
      let browserInfo = 'Unknown Browser';
      
      if (userAgent.includes('Chrome')) browserInfo = 'Chrome';
      else if (userAgent.includes('Firefox')) browserInfo = 'Firefox';
      else if (userAgent.includes('Safari')) browserInfo = 'Safari';
      else if (userAgent.includes('Edge')) browserInfo = 'Edge';
      
      if (userAgent.includes('iPhone')) deviceInfo = 'iPhone';
      else if (userAgent.includes('iPad')) deviceInfo = 'iPad';
      else if (userAgent.includes('Android')) deviceInfo = 'Android';
      else if (userAgent.includes('Windows')) deviceInfo = 'Windows';
      else if (userAgent.includes('Mac')) deviceInfo = 'Mac';
      else if (userAgent.includes('Linux')) deviceInfo = 'Linux';

      return {
        id: session.id,
        ipAddress: session.ipAddress,
        device: `${deviceInfo} - ${browserInfo}`, // Combined device and browser info
        current: isCurrentSession,
        expires: session.expires,
        lastActive: session.expires, // Use expires as a proxy for session activity
        location: session.ipAddress // Use IP address as location for now
      };
    });

    return NextResponse.json({
      success: true,
      data: {
        sessions: sessionsWithInfo,
        currentSessionId: currentSessionId
      }
    });

  } catch (error) {
    console.error('Sessions fetch error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
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

    // Get parameters from both URL search params and request body
    const { searchParams } = new URL(request.url);
    let sessionId = searchParams.get('sessionId');
    let action = searchParams.get('action');
    
    // If not in URL params, check request body
    if (!sessionId && !action) {
      try {
        const body = await request.json();
        sessionId = body.sessionId;
        action = body.action;
      } catch (e) {
        // Body parsing failed, continue with URL params only
      }
    }

    const userId = authResult.data.user.id;
    const currentSessionId = authResult.data.session.id;

    if (action === 'terminate-all-others') {
      // Terminate all sessions except current
      const deletedSessions = await prisma.session.deleteMany({
        where: {
          userId,
          id: {
            not: currentSessionId
          }
        }
      });

      // Log security event
      await logSecurityEvent({
        userId,
        event: 'sessions_terminated',
        details: {
          action: 'all_others',
          terminatedCount: deletedSessions.count,
          triggeredBy: 'user'
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      return NextResponse.json({
        success: true,
        message: `${deletedSessions.count} sessions terminated successfully`
      });

    } else if (sessionId) {
      // Terminate specific session
      if (sessionId === currentSessionId) {
        return NextResponse.json({
          success: false,
          error: 'Cannot terminate your current session. Use logout instead.'
        }, { status: 400 });
      }

      const deletedSession = await prisma.session.deleteMany({
        where: {
          id: sessionId,
          userId
        }
      });

      if (deletedSession.count === 0) {
        return NextResponse.json({
          success: false,
          error: 'Session not found'
        }, { status: 404 });
      }

      // Log security event
      await logSecurityEvent({
        userId,
        event: 'session_terminated',
        details: {
          sessionId,
          triggeredBy: 'user'
        },
        ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
        userAgent: request.headers.get('user-agent') || ''
      });

      return NextResponse.json({
        success: true,
        message: 'Session terminated successfully'
      });

    } else {
      return NextResponse.json({
        success: false,
        error: 'Session ID or action is required'
      }, { status: 400 });
    }

  } catch (error) {
    console.error('Session termination error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
