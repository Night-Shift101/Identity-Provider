/**
 * Authentication Helper Functions
 * Server-side authentication utilities for API routes
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { sessionDb } from '@/lib/database';

/**
 * Middleware to validate user authentication
 * @param {Request} request - Next.js request object
 * @returns {Promise<NextResponse|null>} - Response or null to continue
 */
export async function authMiddleware(request) {
  const pathname = request.nextUrl.pathname;
  
  // Define protected routes
  const protectedRoutes = [
    '/api/auth/mfa',
    '/api/auth/logout',
    '/api/account',
    '/api/devices',
    '/api/security',
    '/dashboard',
    '/account',
    '/security'
  ];

  // Check if route needs protection
  const isProtectedRoute = protectedRoutes.some(route => 
    pathname.startsWith(route)
  );

  if (!isProtectedRoute) {
    return null; // Not a protected route, continue
  }

  try {
    // Get session token from cookie or Authorization header
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return new NextResponse(
        JSON.stringify({ 
          success: false, 
          error: 'Authentication required' 
        }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // Verify session
    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return new NextResponse(
        JSON.stringify({ 
          success: false, 
          error: 'Invalid session' 
        }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    const session = sessionResult.data;

    // Check if user still exists (critical security check)
    if (!session.user) {
      // Session exists but user was deleted - invalidate session
      await sessionDb.delete(sessionToken);
      return new NextResponse(
        JSON.stringify({ 
          success: false, 
          error: 'Account no longer exists' 
        }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // Check if session has expired
    if (new Date() > session.expires) {
      return new NextResponse(
        JSON.stringify({ 
          success: false, 
          error: 'Session expired' 
        }),
        { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // Check if user is active
    if (!session.user.isActive) {
      return new NextResponse(
        JSON.stringify({ 
          success: false, 
          error: 'Account inactive' 
        }),
        { 
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // Add user info to request headers for use in API routes
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-user-id', session.user.id);
    requestHeaders.set('x-user-email', session.user.email);
    requestHeaders.set('x-session-id', session.id);

    return NextResponse.next({
      request: {
        headers: requestHeaders,
      }
    });

  } catch (error) {
    console.error('Auth middleware error:', error);
    
    return new NextResponse(
      JSON.stringify({ 
        success: false, 
        error: 'Authentication error' 
      }),
      { 
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      }
    );
  }
}

/**
 * Get authenticated user from request
 * @param {Request} request - Next.js request object
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function getAuthenticatedUser(request) {
  try {
    // Get session token from cookie or Authorization header
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return {
        success: false,
        error: 'No authentication token provided',
        data: null
      };
    }

    // Verify session
    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return {
        success: false,
        error: 'Invalid session',
        data: null
      };
    }

    const session = sessionResult.data;

    // Check if user still exists (critical security check)
    if (!session.user) {
      // Session exists but user was deleted - invalidate session
      await sessionDb.delete(sessionToken);
      return {
        success: false,
        error: 'Account no longer exists',
        data: null
      };
    }

    // Check if session has expired
    if (new Date() > session.expires) {
      return {
        success: false,
        error: 'Session expired',
        data: null
      };
    }

    // Check if user is active
    if (!session.user.isActive) {
      return {
        success: false,
        error: 'Account inactive',
        data: null
      };
    }

    return {
      success: true,
      error: null,
      data: {
        user: session.user,
        session: {
          id: session.id,
          token: session.sessionToken,
          expires: session.expires
        }
      }
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Authentication error',
      data: null
    };
  }
}

/**
 * Check if user has specific permissions (for future role-based access)
 * @param {Object} user - User object
 * @param {string[]} requiredPermissions - Required permissions
 * @returns {boolean} - Has permissions
 */
export function hasPermissions(user, requiredPermissions = []) {
  // For now, just check if user is active and verified
  // This can be extended with role-based permissions in the future
  if (!user.isActive) return false;
  
  // Add more permission checks here as needed
  return true;
}

/**
 * Rate limiting helper (basic implementation)
 * @param {string} identifier - IP address or user ID
 * @param {number} maxRequests - Maximum requests allowed
 * @param {number} windowMs - Time window in milliseconds
 * @returns {Promise<{allowed: boolean, remaining: number}>}
 */
export async function checkRateLimit(identifier, maxRequests = 100, windowMs = 15 * 60 * 1000) {
  // This is a basic in-memory rate limiter
  // In production, use Redis or a proper rate limiting service
  
  if (!global.rateLimitStore) {
    global.rateLimitStore = new Map();
  }

  const now = Date.now();
  const windowStart = now - windowMs;
  
  // Get existing requests for this identifier
  let requests = global.rateLimitStore.get(identifier) || [];
  
  // Remove old requests outside the time window
  requests = requests.filter(timestamp => timestamp > windowStart);
  
  // Check if limit is exceeded
  if (requests.length >= maxRequests) {
    return {
      allowed: false,
      remaining: 0
    };
  }

  // Add current request
  requests.push(now);
  global.rateLimitStore.set(identifier, requests);

  return {
    allowed: true,
    remaining: maxRequests - requests.length
  };
}
