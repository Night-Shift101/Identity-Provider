/**
 * Lightweight session validation for Next.js Edge Middleware
 * Provides secure session checking aligned with database session system
 * 
 * ARCHITECTURE NOTE:
 * - Database sessions are stored in the 'sessions' table with random tokens
 * - Edge middleware does lightweight validation (format, basic security)
 * - Full session validation (expiry, user existence) happens in API routes with database access
 * - This approach balances security with Edge runtime limitations
 * 
 * @author IdP System
 */

/**
 * Validate session token format and basic structure (lightweight validation)
 * Note: Full session validation requires database access and happens in API routes
 * @param {string} sessionToken - Database session token
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export async function validateSessionAtEdge(sessionToken) {
  try {
    if (!sessionToken) {
      return {
        success: false,
        error: 'No session token provided',
        data: null
      };
    }

    // Basic token format validation (UUID-like format for database tokens)
    // Session tokens should be at least 32 characters (crypto-secure random)
    if (sessionToken.length < 32) {
      return {
        success: false,
        error: 'Invalid session token format',
        data: null
      };
    }

    // Check for valid characters (alphanumeric + some symbols)
    const validTokenPattern = /^[a-zA-Z0-9\-_\.]+$/;
    if (!validTokenPattern.test(sessionToken)) {
      return {
        success: false,
        error: 'Invalid session token characters',
        data: null
      };
    }

    // Edge validation passes - full validation happens in API routes with database access
    return {
      success: true,
      error: null,
      data: {
        token: sessionToken,
        validated: 'edge-only' // Indicates this is lightweight validation
      }
    };

  } catch (error) {
    console.error('Edge session validation error:', error);
    
    return {
      success: false,
      error: 'Session validation failed',
      data: null
    };
  }
}

/**
 * Extract session token from request cookies
 * @param {Request} request - Next.js request object
 * @returns {string|null} Session token or null if not found
 */
export function extractSessionToken(request) {
  try {
    // First try to get from 'session' cookie (main session storage)
    const sessionCookie = request.cookies.get('session')?.value;
    if (sessionCookie) {
      return sessionCookie;
    }

    // Fallback: check Authorization header
    const authHeader = request.headers.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.replace('Bearer ', '');
    }

    // Legacy: check for 'session-token' cookie name
    const cookies = request.headers.get('cookie');
    if (cookies) {
      const cookieArray = cookies.split(';');
      for (const cookie of cookieArray) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'session-token') {
          return decodeURIComponent(value);
        }
      }
    }

    return null;
  } catch (error) {
    console.error('Error extracting session token:', error);
    return null;
  }
}

/**
 * Check if user has required permissions for a route
 * Note: This is basic route access control. Full permission checking happens in API routes
 * @param {Object} sessionData - Lightweight session data from edge validation
 * @param {string} pathname - Request pathname
 * @returns {{ hasAccess: boolean, reason?: string }}
 */
export function checkRoutePermissions(sessionData, pathname) {
  try {
    // Since edge validation is lightweight, we do basic route access control
    // Full permission checking with user roles happens in the API routes with database access
    
    // Admin routes - will be validated in API routes with proper role checking
    if (pathname.startsWith('/admin/')) {
      return { 
        hasAccess: true, // Allow through to API route for proper validation
        reason: 'Admin route - validation deferred to API'
      };
    }

    // MFA routes - allow authenticated users
    if (pathname.startsWith('/auth/mfa') || pathname.includes('mfa')) {
      return { hasAccess: true };
    }

    // API routes - allow authenticated users, detailed permissions checked in API handlers
    if (pathname.startsWith('/api/')) {
      return { hasAccess: true };
    }

    // Default: allow access for users with valid session tokens
    return { hasAccess: true };

  } catch (error) {
    console.error('Route permission check error:', error);
    return {
      hasAccess: false,
      reason: 'Permission check failed'
    };
  }
}

/**
 * Get secure headers for authenticated requests
 * @param {Object} sessionData - Session data from edge validation
 * @returns {Headers} Headers object with security context
 */
export function getSecureHeaders(sessionData) {
  const headers = new Headers();
  
  // Add session token for API route validation
  if (sessionData.token) {
    headers.set('x-session-token', sessionData.token);
  }
  
  // Add security headers
  headers.set('x-authenticated', 'true');
  headers.set('x-session-validated', sessionData.validated || 'edge');
  
  return headers;
}
