/**
 * WebAuthn Authentication Finish API Route
 * Verifies passkey authentication and creates session
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { verifyPasskeyAuthentication } from '@/lib/webauthn';
import { generateSecureToken } from '@/lib/auth';
import { sessionDb } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

export async function POST(request) {
  try {
    const requestBody = await request.json();
    const { challengeKey, ...authenticationResponse } = requestBody;

    if (!authenticationResponse.id || !challengeKey) {
      return NextResponse.json({
        success: false,
        error: 'Missing credential data or challenge key'
      }, { status: 400 });
    }

    // Verify authentication
    const verificationResult = await verifyPasskeyAuthentication(authenticationResponse, challengeKey);

    if (!verificationResult.success) {
      await logSecurityEvent({
        event: 'passkey_authentication_failed',
        details: {
          ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
          userAgent: request.headers.get('user-agent') || 'unknown',
          error: verificationResult.error,
          credentialId: authenticationResponse.id
        }
      });

      return NextResponse.json({
        success: false,
        error: verificationResult.error
      }, { status: 400 });
    }

    const { user, credential } = verificationResult.data;

    // Create session
    const sessionToken = generateSecureToken();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    const session = await sessionDb.create({
      userId: user.id,
      sessionToken,
      expires: expiresAt,
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown'
    });

    // Update credential last used
    // (Already handled in verifyPasskeyAuthentication function)

    // Log successful authentication
    await logSecurityEvent({
      event: 'passkey_authentication_success',
      userId: user.id,
      details: {
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown',
        credentialId: authenticationResponse.credentialId,
        credentialName: credential.name
      }
    });

    // Set session cookie
    const response = NextResponse.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          username: user.username
        }
      }
    });

    response.cookies.set('session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      expires: expiresAt,
      path: '/'
    });

    return response;

  } catch (error) {
    console.error('Authentication finish error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to complete authentication'
    }, { status: 500 });
  }
}
