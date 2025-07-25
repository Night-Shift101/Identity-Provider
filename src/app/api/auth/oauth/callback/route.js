/**
 * OAuth Callback Handler
 * Handles OAuth provider redirects
 * @author IdP System
 */

import { NextResponse } from 'next/server';

export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const error = searchParams.get('error');

    // Handle OAuth errors
    if (error) {
      return NextResponse.redirect(
        `${process.env.APP_URL}/account?oauth_error=${encodeURIComponent(error)}`
      );
    }

    if (!code || !state) {
      return NextResponse.redirect(
        `${process.env.APP_URL}/account?oauth_error=missing_parameters`
      );
    }

    // Redirect to frontend with parameters for client-side handling
    const params = new URLSearchParams({
      code,
      state,
      success: 'true'
    });

    return NextResponse.redirect(
      `${process.env.APP_URL}/account?${params.toString()}`
    );

  } catch (error) {
    console.error('OAuth callback error:', error);
    return NextResponse.redirect(
      `${process.env.APP_URL}/account?oauth_error=callback_failed`
    );
  }
}
