/**
 * Security Logs API Route
 * Provides access to user's security event history
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { prisma } from '@/lib/database';

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
    const { searchParams } = new URL(request.url);
    
    // Parse query parameters
    const limit = parseInt(searchParams.get('limit') || '50');
    const offset = parseInt(searchParams.get('offset') || '0');
    const eventType = searchParams.get('eventType');
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');

    // Build where clause
    const whereClause = {
      userId
    };

    if (eventType) {
      whereClause.event = eventType;
    }

    if (startDate || endDate) {
      whereClause.timestamp = {};
      if (startDate) {
        whereClause.timestamp.gte = new Date(startDate);
      }
      if (endDate) {
        whereClause.timestamp.lte = new Date(endDate);
      }
    }

    // Get security logs
    const [logs, totalCount] = await Promise.all([
      prisma.securityLog.findMany({
        where: whereClause,
        orderBy: {
          timestamp: 'desc'
        },
        take: Math.min(limit, 100), // Max 100 per request
        skip: offset,
        select: {
          id: true,
          event: true,
          details: true,
          ipAddress: true,
          userAgent: true,
          timestamp: true
        }
      }),
      prisma.securityLog.count({
        where: whereClause
      })
    ]);

    // Format logs for display
    const formattedLogs = logs.map(log => ({
      id: log.id,
      event: log.event,
      timestamp: log.timestamp,
      ipAddress: log.ipAddress,
      userAgent: log.userAgent,
      severity: getSeverity(log.event),
      details: typeof log.details === 'string' ? 
        JSON.parse(log.details) : 
        log.details,
      description: getEventDescription(log.event, log.details)
    }));

    return NextResponse.json({
      success: true,
      data: {
        logs: formattedLogs,
        pagination: {
          total: totalCount,
          limit,
          offset,
          hasMore: offset + limit < totalCount
        }
      }
    });

  } catch (error) {
    console.error('Security logs error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to retrieve security logs'
    }, { status: 500 });
  }
}

/**
 * Generate human-readable descriptions for security events
 */
function getEventDescription(eventType, details) {
  const parsedDetails = typeof details === 'string' ? 
    JSON.parse(details) : 
    details;

  switch (eventType) {
    case 'login_success':
      return 'Successful login';
    
    case 'login_failed':
      return `Failed login attempt${parsedDetails?.reason ? ': ' + parsedDetails.reason : ''}`;
    
    case 'logout':
      return 'User logged out';
    
    case 'password_changed':
      return 'Password changed successfully';
    
    case 'password_change_failed':
      return `Password change failed${parsedDetails?.reason ? ': ' + parsedDetails.reason : ''}`;
    
    case 'account_deleted':
      return 'Account deleted';
    
    case 'profile_updated':
      const changes = parsedDetails?.changes ? Object.keys(parsedDetails.changes).join(', ') : 'profile';
      return `Profile updated: ${changes}`;
    
    case 'sessions_terminated':
      const action = parsedDetails?.action;
      const count = parsedDetails?.terminatedCount || 0;
      if (action === 'all_others') {
        return `Terminated ${count} other session${count !== 1 ? 's' : ''}`;
      }
      return 'Session terminated';
    
    case 'device_removed':
      const deviceName = parsedDetails?.deviceName || 'device';
      return `Trusted device removed: ${deviceName}`;
    
    case 'passkey_created':
      const passkeyName = parsedDetails?.name || 'passkey';
      return `Passkey created: ${passkeyName}`;
    
    case 'passkey_deleted':
      return `Passkey deleted: ${parsedDetails?.name || 'unnamed'}`;
    
    case 'oauth_linked':
      const provider = parsedDetails?.provider || 'OAuth provider';
      return `${provider} account linked`;
    
    case 'oauth_unlinked':
      const unlinkedProvider = parsedDetails?.provider || 'OAuth provider';
      return `${unlinkedProvider} account unlinked`;
    
    case 'mfa_enabled':
      return 'Two-factor authentication enabled';
    
    case 'mfa_disabled':
      return 'Two-factor authentication disabled';
    
    case 'suspicious_activity':
      return `Suspicious activity detected${parsedDetails?.type ? ': ' + parsedDetails.type : ''}`;
    
    default:
      return eventType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }
}

/**
 * Determine severity level based on event type
 */
function getSeverity(eventType) {
  switch (eventType) {
    case 'login_failed':
    case 'password_change_failed':
    case 'suspicious_activity':
      return 'warning';
    
    case 'account_deleted':
    case 'mfa_disabled':
      return 'high';
    
    case 'login_success':
    case 'logout':
    case 'password_changed':
    case 'profile_updated':
    case 'sessions_terminated':
    case 'device_removed':
    case 'passkey_created':
    case 'passkey_deleted':
    case 'oauth_linked':
    case 'oauth_unlinked':
    case 'mfa_enabled':
      return 'info';
    
    default:
      return 'info';
  }
}
