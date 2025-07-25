/**
 * MFA Setup API Route
 * Handles TOTP setup, QR code generation, and backup codes
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { generateTotpSecret, generateQrCode, validateMfaSetup, generateBackupCodes } from '@/lib/mfa';
import { userDb, sessionDb } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

// Initialize MFA setup
export async function POST(request) {
  try {
    const { action } = await request.json();
    
    // Get session token from cookie or Authorization header
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      );
    }

    // Get user from session
    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid session' },
        { status: 401 }
      );
    }

    const user = sessionResult.data.user;
    
    // Get client information for logging
    const clientIp = request.headers.get('x-forwarded-for') || 
                     request.headers.get('x-real-ip') || 
                     '127.0.0.1';
    const userAgent = request.headers.get('user-agent') || '';

    switch (action) {
      case 'initialize':
        return await handleInitializeMfa(user, clientIp, userAgent);
      
      case 'verify':
        const { secret, token } = await request.json();
        return await handleVerifyMfa(user, secret, token, clientIp, userAgent);
      
      case 'disable':
        return await handleDisableMfa(user, clientIp, userAgent);
      
      case 'regenerate-backup-codes':
        return await handleRegenerateBackupCodes(user, clientIp, userAgent);
      
      default:
        return NextResponse.json(
          { success: false, error: 'Invalid action' },
          { status: 400 }
        );
    }

  } catch (error) {
    console.error('MFA setup error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

async function handleInitializeMfa(user, clientIp, userAgent) {
  try {
    // Generate TOTP secret
    const secretResult = await generateTotpSecret(user.email);
    if (!secretResult.success) {
      return NextResponse.json(
        { success: false, error: secretResult.error },
        { status: 500 }
      );
    }

    // Generate QR code
    const qrResult = await generateQrCode(secretResult.data.otpauthUrl);
    if (!qrResult.success) {
      return NextResponse.json(
        { success: false, error: qrResult.error },
        { status: 500 }
      );
    }

    // Log security event
    await logSecurityEvent({
      userId: user.id,
      event: 'mfa_setup_initialized',
      details: {
        method: 'totp'
      },
      ipAddress: clientIp,
      userAgent
    });

    return NextResponse.json({
      success: true,
      message: 'MFA setup initialized',
      data: {
        secret: secretResult.data.secret,
        qrCode: qrResult.data,
        manualEntryKey: secretResult.data.manualEntryKey
      }
    }, { status: 200 });

  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to initialize MFA' },
      { status: 500 }
    );
  }
}

async function handleVerifyMfa(user, secret, token, clientIp, userAgent) {
  try {
    if (!secret || !token) {
      return NextResponse.json(
        { success: false, error: 'Secret and token are required' },
        { status: 400 }
      );
    }

    // Validate MFA setup
    const validationResult = await validateMfaSetup({ secret, token });
    if (!validationResult.success || !validationResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid MFA token' },
        { status: 400 }
      );
    }

    // Generate backup codes
    const backupCodesResult = await generateBackupCodes();
    if (!backupCodesResult.success) {
      return NextResponse.json(
        { success: false, error: 'Failed to generate backup codes' },
        { status: 500 }
      );
    }

    // Enable MFA for user
    const updateResult = await userDb.update(user.id, {
      mfaEnabled: true,
      mfaSecret: secret,
      mfaBackupCodes: backupCodesResult.data
    });

    if (!updateResult.success) {
      return NextResponse.json(
        { success: false, error: 'Failed to enable MFA' },
        { status: 500 }
      );
    }

    // Log security event
    await logSecurityEvent({
      userId: user.id,
      event: 'mfa_enabled',
      details: {
        method: 'totp',
        backupCodesGenerated: backupCodesResult.data.length
      },
      ipAddress: clientIp,
      userAgent
    });

    return NextResponse.json({
      success: true,
      message: 'MFA enabled successfully',
      data: {
        backupCodes: backupCodesResult.data,
        user: updateResult.data
      }
    }, { status: 200 });

  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to verify and enable MFA' },
      { status: 500 }
    );
  }
}

async function handleDisableMfa(user, clientIp, userAgent) {
  try {
    if (!user.mfaEnabled) {
      return NextResponse.json(
        { success: false, error: 'MFA is not enabled' },
        { status: 400 }
      );
    }

    // Disable MFA for user
    const updateResult = await userDb.update(user.id, {
      mfaEnabled: false,
      mfaSecret: null,
      mfaBackupCodes: null
    });

    if (!updateResult.success) {
      return NextResponse.json(
        { success: false, error: 'Failed to disable MFA' },
        { status: 500 }
      );
    }

    // Log security event
    await logSecurityEvent({
      userId: user.id,
      event: 'mfa_disabled',
      details: {
        method: 'totp'
      },
      ipAddress: clientIp,
      userAgent
    });

    return NextResponse.json({
      success: true,
      message: 'MFA disabled successfully',
      data: {
        user: updateResult.data
      }
    }, { status: 200 });

  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to disable MFA' },
      { status: 500 }
    );
  }
}

async function handleRegenerateBackupCodes(user, clientIp, userAgent) {
  try {
    if (!user.mfaEnabled) {
      return NextResponse.json(
        { success: false, error: 'MFA is not enabled' },
        { status: 400 }
      );
    }

    // Generate new backup codes
    const backupCodesResult = await generateBackupCodes();
    if (!backupCodesResult.success) {
      return NextResponse.json(
        { success: false, error: 'Failed to generate backup codes' },
        { status: 500 }
      );
    }

    // Update user with new backup codes
    const updateResult = await userDb.update(user.id, {
      mfaBackupCodes: backupCodesResult.data
    });

    if (!updateResult.success) {
      return NextResponse.json(
        { success: false, error: 'Failed to update backup codes' },
        { status: 500 }
      );
    }

    // Log security event
    await logSecurityEvent({
      userId: user.id,
      event: 'mfa_backup_codes_regenerated',
      details: {
        backupCodesCount: backupCodesResult.data.length
      },
      ipAddress: clientIp,
      userAgent
    });

    return NextResponse.json({
      success: true,
      message: 'Backup codes regenerated successfully',
      data: {
        backupCodes: backupCodesResult.data
      }
    }, { status: 200 });

  } catch (error) {
    return NextResponse.json(
      { success: false, error: 'Failed to regenerate backup codes' },
      { status: 500 }
    );
  }
}

// Get MFA status
export async function GET(request) {
  try {
    // Get session token from cookie or Authorization header
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      );
    }

    // Get user from session
    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid session' },
        { status: 401 }
      );
    }

    const user = sessionResult.data.user;

    return NextResponse.json({
      success: true,
      data: {
        mfaEnabled: user.mfaEnabled,
        hasBackupCodes: !!(user.mfaBackupCodes && user.mfaBackupCodes.length > 0),
        backupCodesCount: user.mfaBackupCodes ? user.mfaBackupCodes.length : 0
      }
    }, { status: 200 });

  } catch (error) {
    console.error('MFA status error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
