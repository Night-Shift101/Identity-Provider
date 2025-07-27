/**
 * Development Helper - Clear Session Cookie
 * Removes session cookie to help with testing
 * @author IdP System
 */

import { NextResponse } from 'next/server';

export async function POST() {
  if (process.env.NODE_ENV !== 'development') {
    return NextResponse.json({
      success: false,
      error: 'This endpoint is only available in development'
    }, { status: 403 });
  }

  const response = NextResponse.json({
    success: true,
    message: 'Session cookie cleared'
  });

  // Clear the session cookie
  response.cookies.delete('session');

  return response;
}
