/**
 * Passkey Registration API Routes
 * Handles passkey registration start and finish
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { generatePasskeyRegistrationOptions, verifyPasskeyRegistration } from '@/lib/webauthn';
import { logSecurityEvent } from '@/lib/security';

/**
 * POST /api/auth/passkeys/register
 * Handle passkey registration start and finish
 */
export async function POST(request) {
  try {
    const { action, ...data } = await request.json();

    switch (action) {
      case 'start':
        return await handleRegistrationStart(request);
      
      case 'finish':
        return await handleRegistrationFinish(request, data);
      
      default:
        return NextResponse.json({
          success: false,
          error: 'Invalid action'
        }, { status: 400 });
    }

  } catch (error) {
    console.error('Passkey registration API error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

/**
 * Start passkey registration process
 */
async function handleRegistrationStart(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const user = authResult.data.user;

    // Generate registration options
    const optionsResult = await generatePasskeyRegistrationOptions(user);
    
    if (!optionsResult.success) {
      return NextResponse.json({
        success: false,
        error: optionsResult.error
      }, { status: 400 });
    }

    // Log security event
    await logSecurityEvent(user.id, 'passkey_registration_started', {
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown'
    });

    return NextResponse.json({
      success: true,
      data: optionsResult.data
    });

  } catch (error) {
    console.error('Registration start error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to start registration'
    }, { status: 500 });
  }
}

/**
 * Finish passkey registration process
 */
async function handleRegistrationFinish(request, data) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const user = authResult.data.user;
    const { registrationResponse, credentialName } = data;

    if (!registrationResponse || !credentialName) {
      return NextResponse.json({
        success: false,
        error: 'Missing registration data or credential name'
      }, { status: 400 });
    }

    // Verify registration
    const verificationResult = await verifyPasskeyRegistration(
      user, 
      registrationResponse, 
      credentialName.trim()
    );

    if (!verificationResult.success) {
      await logSecurityEvent(user.id, 'passkey_registration_failed', {
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown',
        error: verificationResult.error
      });

      return NextResponse.json({
        success: false,
        error: verificationResult.error
      }, { status: 400 });
    }

    // Log successful registration
    await logSecurityEvent(user.id, 'passkey_registered', {
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
      credentialName: credentialName.trim(),
      credentialId: verificationResult.data.credentialId
    });

    return NextResponse.json({
      success: true,
      data: {
        credentialId: verificationResult.data.credentialId,
        message: 'Passkey registered successfully'
      }
    });

  } catch (error) {
    console.error('Registration finish error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to complete registration'
    }, { status: 500 });
  }
}
