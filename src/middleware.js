/**
 * Next.js Edge Middleware
 * Handles routing, redirects, and secure authentication checks at the edge
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { validateSessionAtEdge, extractSessionToken, checkRoutePermissions, getSecureHeaders } from '@/lib/middleware-auth';

export async function middleware(request) {
  const pathname = request.nextUrl.pathname;
  
  // Skip middleware for static files and public API routes
  const publicPaths = [
    '/_next/',
    '/static/',
    '/public/',
    '/favicon.ico',
    '/api/auth/register',
    '/api/auth/login', 
    '/api/auth/verify-email',
    '/api/auth/resend-verification',
    '/api/auth/oauth',
    '/api/test/email' // Development only
  ];

  const isPublicPath = publicPaths.some(path => pathname.startsWith(path)) || 
                      pathname.includes('.') || 
                      pathname === '/';

  if (isPublicPath) {
    return NextResponse.next();
  }

  // Handle authentication for protected routes
  return await handleAuthentication(request);
}

async function handleAuthentication(request) {
  const pathname = request.nextUrl.pathname;
  
  try {
    // Define which routes require authentication
    const protectedRoutes = [
      '/dashboard',
      '/account',
      '/security', 
      '/devices',
      '/api/auth/mfa',
      '/api/auth/logout',
      '/api/auth/change-password',
      '/api/auth/delete-account',
      '/api/account/',
      '/api/devices/',
      '/api/security/'
    ];

    const authRoutes = [
      '/auth/login',
      '/auth/register', 
      '/auth/verify-email',
      '/auth/mfa'
    ];

    const isProtectedRoute = protectedRoutes.some(route => pathname.startsWith(route));
    const isAuthRoute = authRoutes.some(route => pathname.startsWith(route));

    // Extract session token from cookies
    const sessionToken = extractSessionToken(request);

    // Handle protected routes
    if (isProtectedRoute) {
      if (!sessionToken) {
        return redirectToLogin(request, pathname);
      }

      // Validate session token at the edge - SECURITY FIX: Proper session validation
      const sessionValidation = await validateSessionAtEdge(sessionToken);
      
      if (!sessionValidation.success) {
        // Session invalid - clear cookie and redirect to login
        const response = redirectToLogin(request, pathname);
        response.cookies.delete('session'); // Use correct cookie name
        return response;
      }

      // Check route-specific permissions
      const permissionCheck = checkRoutePermissions(sessionValidation.data, pathname);
      if (!permissionCheck.hasAccess) {
        // Insufficient permissions
        if (pathname.startsWith('/api/')) {
          return new NextResponse(
            JSON.stringify({
              success: false,
              error: permissionCheck.reason || 'Insufficient permissions',
              data: null
            }),
            { 
              status: 403,
              headers: { 'Content-Type': 'application/json' }
            }
          );
        } else {
          // Redirect to dashboard with error
          const dashboardUrl = new URL('/dashboard', request.url);
          dashboardUrl.searchParams.set('error', 'insufficient_permissions');
          return NextResponse.redirect(dashboardUrl);
        }
      }

      // Add secure headers for API routes
      if (pathname.startsWith('/api/')) {
        const secureHeaders = getSecureHeaders(sessionValidation.data);
        
        return NextResponse.next({
          request: {
            headers: secureHeaders,
          }
        });
      }

      // Allow access to protected pages
      return NextResponse.next();
    }

    // Handle auth routes (redirect if already authenticated)
    if (isAuthRoute && sessionToken) {
      const sessionValidation = await validateSessionAtEdge(sessionToken);
      
      if (sessionValidation.success) {
        // Already authenticated - redirect to dashboard unless it's email verification
        if (pathname !== '/auth/verify-email') {
          return NextResponse.redirect(new URL('/dashboard', request.url));
        }
      }
    }

    return NextResponse.next();

  } catch (error) {
    console.error('Middleware authentication error:', error);
    
    // For API routes, return structured error response
    if (pathname.startsWith('/api/')) {
      return new NextResponse(
        JSON.stringify({ 
          success: false, 
          error: 'Authentication system error',
          data: null
        }),
        { 
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // For web pages, redirect to login
    return redirectToLogin(request, pathname);
  }
}

/**
 * Create login redirect response with return URL
 * @param {Request} request - Next.js request
 * @param {string} returnPath - Path to return to after login
 * @returns {NextResponse} Redirect response
 */
function redirectToLogin(request, returnPath) {
  const loginUrl = new URL('/auth/login', request.url);
  if (returnPath && returnPath !== '/') {
    loginUrl.searchParams.set('redirect', returnPath);
  }
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     */
    '/((?!_next/static|_next/image|favicon.ico|public/).*)',
  ],
};
