/**
 * WebAuthn/Passkeys API Routes
 * Handles passkey registration and authentication
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { 
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthenticationOptions,
  verifyPasskeyAuthentication,
  getUserPasskeys,
  deletePasskey,
  renamePasskey
} from '@/lib/webauthn';
import { sessionDb, userDb } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

export async function POST(request) {
  try {
    const { action } = await request.json();
    
    switch (action) {
      case 'generate-registration-options':
        return await handleGenerateRegistrationOptions(request);
      
      case 'verify-registration':
        return await handleVerifyRegistration(request);
      
      case 'generate-authentication-options':
        return await handleGenerateAuthenticationOptions(request);
      
      case 'verify-authentication':
        return await handleVerifyAuthentication(request);
      
      case 'delete-passkey':
        return await handleDeletePasskey(request);
      
      case 'rename-passkey':
        return await handleRenamePasskey(request);
      
      default:
        return NextResponse.json(
          { success: false, error: 'Invalid action' },
          { status: 400 }
        );
    }

  } catch (error) {
    console.error('WebAuthn API error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET(request) {
  try {
    // Get user's passkeys
    const sessionToken = request.cookies.get('session')?.value ||
                         request.headers.get('authorization')?.replace('Bearer ', '');

    if (!sessionToken) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      );
    }

    const sessionResult = await sessionDb.findByToken(sessionToken);
    if (!sessionResult.success || !sessionResult.data) {
      return NextResponse.json(
        { success: false, error: 'Invalid session' },
        { status: 401 }
      );
    }

    const user = sessionResult.data.user;
    
    const passkeysResult = await getUserPasskeys(user.id);
    if (!passkeysResult.success) {
      return NextResponse.json(
        { success: false, error: passkeysResult.error },
        { status: 500 }
      );
    }

    return NextResponse.json({
      success: true,
      data: {
        passkeys: passkeysResult.data
      }
    }, { status: 200 });

  } catch (error) {
    console.error('Get passkeys error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}

async function handleGenerateRegistrationOptions(request) {
  // Get authenticated user
  const sessionToken = request.cookies.get('session')?.value ||
                       request.headers.get('authorization')?.replace('Bearer ', '');

  if (!sessionToken) {
    return NextResponse.json(
      { success: false, error: 'Authentication required' },
      { status: 401 }
    );
  }

  const sessionResult = await sessionDb.findByToken(sessionToken);
  if (!sessionResult.success || !sessionResult.data) {
    return NextResponse.json(
      { success: false, error: 'Invalid session' },
      { status: 401 }
    );
  }

  const user = sessionResult.data.user;
  
  const optionsResult = await generatePasskeyRegistrationOptions(user);
  if (!optionsResult.success) {
    return NextResponse.json(
      { success: false, error: optionsResult.error },
      { status: 500 }
    );
  }

  return NextResponse.json({
    success: true,
    data: optionsResult.data
  }, { status: 200 });
}

async function handleVerifyRegistration(request) {
  const { registrationResponse, credentialName } = await request.json();
  
  // Get authenticated user
  const sessionToken = request.cookies.get('session')?.value ||
                       request.headers.get('authorization')?.replace('Bearer ', '');

  if (!sessionToken) {
    return NextResponse.json(
      { success: false, error: 'Authentication required' },
      { status: 401 }
    );
  }

  const sessionResult = await sessionDb.findByToken(sessionToken);
  if (!sessionResult.success || !sessionResult.data) {
    return NextResponse.json(
      { success: false, error: 'Invalid session' },
      { status: 401 }
    );
  }

  const user = sessionResult.data.user;
  
  const verificationResult = await verifyPasskeyRegistration(
    user, 
    registrationResponse, 
    credentialName
  );

  if (!verificationResult.success) {
    return NextResponse.json(
      { success: false, error: verificationResult.error },
      { status: 400 }
    );
  }

  // Log security event
  const clientIp = request.headers.get('x-forwarded-for') || 
                   request.headers.get('x-real-ip') || 
                   '127.0.0.1';
  const userAgent = request.headers.get('user-agent') || '';

  await logSecurityEvent({
    userId: user.id,
    event: 'passkey_registered',
    details: {
      credentialName: credentialName || 'Unnamed Passkey',
      deviceType: verificationResult.data.credential.deviceType
    },
    ipAddress: clientIp,
    userAgent
  });

  return NextResponse.json({
    success: true,
    message: 'Passkey registered successfully',
    data: verificationResult.data
  }, { status: 201 });
}

async function handleGenerateAuthenticationOptions(request) {
  const { userEmail } = await request.json();
  
  const optionsResult = await generatePasskeyAuthenticationOptions(userEmail);
  if (!optionsResult.success) {
    return NextResponse.json(
      { success: false, error: optionsResult.error },
      { status: 500 }
    );
  }

  return NextResponse.json({
    success: true,
    data: optionsResult.data
  }, { status: 200 });
}

async function handleVerifyAuthentication(request) {
  const { authenticationResponse, challengeKey } = await request.json();
  
  const verificationResult = await verifyPasskeyAuthentication(
    authenticationResponse, 
    challengeKey
  );

  if (!verificationResult.success) {
    return NextResponse.json(
      { success: false, error: verificationResult.error },
      { status: 400 }
    );
  }

  // Log successful passkey authentication
  const clientIp = request.headers.get('x-forwarded-for') || 
                   request.headers.get('x-real-ip') || 
                   '127.0.0.1';
  const userAgent = request.headers.get('user-agent') || '';

  await logSecurityEvent({
    userId: verificationResult.data.user.id,
    event: 'passkey_authentication_success',
    details: {
      credentialName: verificationResult.data.credential.name
    },
    ipAddress: clientIp,
    userAgent
  });

  // For passkey authentication, you might want to create a session here
  // This depends on your authentication flow

  return NextResponse.json({
    success: true,
    message: 'Passkey authentication successful',
    data: {
      user: {
        id: verificationResult.data.user.id,
        email: verificationResult.data.user.email,
        firstName: verificationResult.data.user.firstName,
        lastName: verificationResult.data.user.lastName
      },
      credential: verificationResult.data.credential
    }
  }, { status: 200 });
}

async function handleDeletePasskey(request) {
  const { credentialId } = await request.json();
  
  // Get authenticated user
  const sessionToken = request.cookies.get('session')?.value ||
                       request.headers.get('authorization')?.replace('Bearer ', '');

  if (!sessionToken) {
    return NextResponse.json(
      { success: false, error: 'Authentication required' },
      { status: 401 }
    );
  }

  const sessionResult = await sessionDb.findByToken(sessionToken);
  if (!sessionResult.success || !sessionResult.data) {
    return NextResponse.json(
      { success: false, error: 'Invalid session' },
      { status: 401 }
    );
  }

  const user = sessionResult.data.user;
  
  const deleteResult = await deletePasskey(user.id, credentialId);
  if (!deleteResult.success) {
    return NextResponse.json(
      { success: false, error: deleteResult.error },
      { status: 500 }
    );
  }

  // Log security event
  const clientIp = request.headers.get('x-forwarded-for') || 
                   request.headers.get('x-real-ip') || 
                   '127.0.0.1';
  const userAgent = request.headers.get('user-agent') || '';

  await logSecurityEvent({
    userId: user.id,
    event: 'passkey_deleted',
    details: {
      credentialId
    },
    ipAddress: clientIp,
    userAgent
  });

  return NextResponse.json({
    success: true,
    message: 'Passkey deleted successfully'
  }, { status: 200 });
}

async function handleRenamePasskey(request) {
  const { credentialId, newName } = await request.json();
  
  // Get authenticated user
  const sessionToken = request.cookies.get('session')?.value ||
                       request.headers.get('authorization')?.replace('Bearer ', '');

  if (!sessionToken) {
    return NextResponse.json(
      { success: false, error: 'Authentication required' },
      { status: 401 }
    );
  }

  const sessionResult = await sessionDb.findByToken(sessionToken);
  if (!sessionResult.success || !sessionResult.data) {
    return NextResponse.json(
      { success: false, error: 'Invalid session' },
      { status: 401 }
    );
  }

  const user = sessionResult.data.user;
  
  const renameResult = await renamePasskey(user.id, credentialId, newName);
  if (!renameResult.success) {
    return NextResponse.json(
      { success: false, error: renameResult.error },
      { status: 500 }
    );
  }

  return NextResponse.json({
    success: true,
    message: 'Passkey renamed successfully',
    data: renameResult.data
  }, { status: 200 });
}
