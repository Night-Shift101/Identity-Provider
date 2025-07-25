/**
 * Next.js Edge Middleware
 * Handles routing, redirects, and basic authentication checks at the edge
 * @author IdP System
 */

import { NextResponse } from 'next/server';

export function middleware(request) {
  const pathname = request.nextUrl.pathname;
  
  // Skip middleware for static files and API routes that don't need auth
  if (
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/static/') ||
    pathname.includes('.') ||
    pathname === '/api/auth/register' ||
    pathname === '/api/auth/login' ||
    pathname === '/api/auth/verify-email' ||
    pathname === '/favicon.ico'
  ) {
    return NextResponse.next();
  }

  // Handle authentication for protected routes
  return handleAuthentication(request);
}

async function handleAuthentication(request) {
  const pathname = request.nextUrl.pathname;
  
  // Define which routes require authentication
  const protectedRoutes = [
    '/dashboard',
    '/account',
    '/security',
    '/devices',
    '/api/auth/mfa',
    '/api/auth/logout',
    '/api/account',
    '/api/devices',
    '/api/security'
  ];

  const isProtectedRoute = protectedRoutes.some(route => 
    pathname.startsWith(route)
  );

  // Public routes that don't need auth
  const publicRoutes = [
    '/',
    '/auth/login',
    '/auth/register',
    '/auth/verify-email',
    '/auth/forgot-password',
    '/auth/reset-password'
  ];

  const isPublicRoute = publicRoutes.some(route => 
    pathname === route || pathname.startsWith(route)
  );

  if (!isProtectedRoute && !isPublicRoute) {
    // Default behavior for undefined routes
    return NextResponse.next();
  }

  try {
    // Get session token from cookie
    const sessionToken = request.cookies.get('session')?.value;

    // For protected routes, check authentication
    if (isProtectedRoute) {
      if (!sessionToken) {
        // Redirect to login for web pages, return 401 for API routes
        if (pathname.startsWith('/api/')) {
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
        } else {
          const loginUrl = new URL('/auth/login', request.url);
          loginUrl.searchParams.set('redirect', pathname);
          return NextResponse.redirect(loginUrl);
        }
      }

      // For now, we'll do a basic check. In a full implementation,
      // you'd validate the session here, but that requires database access
      // which is better handled in the API routes themselves.
      
      // Add user context headers for API routes
      if (pathname.startsWith('/api/')) {
        const requestHeaders = new Headers(request.headers);
        requestHeaders.set('x-session-token', sessionToken);
        
        return NextResponse.next({
          request: {
            headers: requestHeaders,
          }
        });
      }
    }

    // For public routes, redirect to dashboard if already authenticated
    if (isPublicRoute && sessionToken && !pathname.startsWith('/api/')) {
      // Check if it's an auth page and user is already logged in
      if (pathname.startsWith('/auth/') && pathname !== '/auth/verify-email') {
        return NextResponse.redirect(new URL('/dashboard', request.url));
      }
    }

    return NextResponse.next();

  } catch (error) {
    console.error('Middleware error:', error);
    
    // For API routes, return error response
    if (pathname.startsWith('/api/')) {
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

    // For web pages, redirect to login
    return NextResponse.redirect(new URL('/auth/login', request.url));
  }
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
