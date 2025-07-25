/**
 * Security Logs API Route
 * Handles security events and audit logs
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

    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = Math.min(parseInt(searchParams.get('limit') || '20'), 100); // Max 100 per page
    const eventType = searchParams.get('event');
    const startDate = searchParams.get('startDate');
    const endDate = searchParams.get('endDate');

    const userId = authResult.data.user.id;
    const offset = (page - 1) * limit;

    // Build where clause
    const where = { userId };
    
    if (eventType) {
      where.event = eventType;
    }
    
    if (startDate || endDate) {
      where.timestamp = {};
      if (startDate) {
        where.timestamp.gte = new Date(startDate);
      }
      if (endDate) {
        where.timestamp.lte = new Date(endDate);
      }
    }

    // Get security logs
    const [logs, totalCount] = await Promise.all([
      prisma.securityLog.findMany({
        where,
        select: {
          id: true,
          event: true,
          details: true,
          ipAddress: true,
          userAgent: true,
          timestamp: true
        },
        orderBy: { timestamp: 'desc' },
        skip: offset,
        take: limit
      }),
      prisma.securityLog.count({ where })
    ]);

    // Get recent login activity
    const loginActivity = await prisma.loginActivity.findMany({
      where: { 
        userId,
        timestamp: {
          gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
        }
      },
      select: {
        id: true,
        ipAddress: true,
        userAgent: true,
        location: true,
        country: true,
        city: true,
        success: true,
        failureReason: true,
        timestamp: true
      },
      orderBy: { timestamp: 'desc' },
      take: 10
    });

    return NextResponse.json({
      success: true,
      data: {
        logs,
        loginActivity,
        pagination: {
          page,
          limit,
          total: totalCount,
          pages: Math.ceil(totalCount / limit)
        }
      }
    });

  } catch (error) {
    console.error('Security logs fetch error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}
