/**
 * WebAuthn Authentication Start API Route
 * Generates authentication options for passkey login
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { generatePasskeyAuthenticationOptions } from '@/lib/webauthn';
import { logSecurityEvent } from '@/lib/security';

export async function POST(request) {
  try {
    // No need to parse body for authentication start - we can determine user from any existing passkeys
    const result = await generatePasskeyAuthenticationOptions();
    
    if (!result.success) {
      return NextResponse.json({
        success: false,
        error: result.error
      }, { status: 400 });
    }

    return NextResponse.json({
      success: true,
      challengeKey: result.data.challengeKey,
      ...result.data.options  // Spread the options directly
    });

  } catch (error) {
    console.error('Authentication start error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to start authentication'
    }, { status: 500 });
  }
}
