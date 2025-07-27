/**
 * WebAuthn/Passkeys utilities
 * Handles passkey registration, authentication, and credential management
 * @author IdP System
 */

import { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';
import { prisma } from './database.js';
import { generateSecureToken } from './auth.js';
import { 
  storeWebAuthnRegistrationChallenge,
  storeWebAuthnAuthenticationChallenge,
  retrieveWebAuthnRegistrationChallenge,
  retrieveWebAuthnAuthenticationChallenge,
  cleanupExpiredChallenges
} from './challenge-storage.js';

// Base64URL encoding/decoding helpers
function base64urlToBuffer(base64url) {
  // Convert base64url to base64
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if necessary
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  return Buffer.from(padded, 'base64');
}

function bufferToBase64url(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// WebAuthn configuration - using environment variables for security
const rpName = process.env.APP_NAME || 'Identity Provider';
const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';
const origin = process.env.APP_URL || 'http://localhost:3000';

// Configuration validation
if (!process.env.WEBAUTHN_RP_ID && process.env.NODE_ENV === 'production') {
  console.warn('WEBAUTHN_RP_ID not set in production - using localhost fallback');
}

/**
 * Generate registration options for new passkey
 * @param {Object} user - User object
 * @param {string} [excludeCredentials] - Existing credentials to exclude
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function generatePasskeyRegistrationOptions(user, excludeCredentials = []) {
  try {
    // Get user's existing credentials
    const existingCredentials = await prisma.webAuthnCredential.findMany({
      where: { userId: user.id },
      select: {
        credentialId: true,
        // transports would be stored if we tracked them
      }
    });

    const excludeCredentialsList = existingCredentials.map(cred => ({
      id: cred.credentialId,
      type: 'public-key',
    }));

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: user.id,
      userName: user.email,
      userDisplayName: user.firstName ? `${user.firstName} ${user.lastName || ''}`.trim() : user.email,
      timeout: parseInt(process.env.WEBAUTHN_CHALLENGE_TIMEOUT_MS || '60000'),
      attestationType: 'none',
      excludeCredentials: excludeCredentialsList,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform', // Prefer platform authenticators (Face ID, Touch ID, Windows Hello)
      },
      supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
    });

    // Store challenge securely with automatic expiry
    const challengeResult = storeWebAuthnRegistrationChallenge(user.id, {
      challenge: options.challenge,
      userHandle: options.user.id,
      rpId: rpID
    });

    if (!challengeResult.success) {
      return {
        success: false,
        error: `Failed to store registration challenge: ${challengeResult.error}`,
        data: null
      };
    }

    return {
      success: true,
      error: null,
      data: options
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Failed to generate registration options',
      data: null
    };
  }
}

/**
 * Verify passkey registration response
 * @param {Object} user - User object
 * @param {Object} registrationResponse - WebAuthn registration response
 * @param {string} credentialName - User-provided name for the credential
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function verifyPasskeyRegistration(user, registrationResponse, credentialName) {
  try {
    // Get stored challenge securely
    const challengeResult = retrieveWebAuthnRegistrationChallenge(user.id);
    
    if (!challengeResult.success) {
      return {
        success: false,
        error: `Registration challenge error: ${challengeResult.error}`,
        data: null
      };
    }

    const storedChallenge = challengeResult.data;

    // Check timeout
    // TODO: CONFIGURATION - Make challenge timeout configurable via environment variables
    const challengeTimeout = parseInt(process.env.WEBAUTHN_CHALLENGE_TIMEOUT_MS || '300000'); // 5 minutes
    if (Date.now() - new Date(storedChallenge.timestamp).getTime() > challengeTimeout) {
      return {
        success: false,
        error: 'Registration challenge has expired',
        data: null
      };
    }

    // Verify the registration response
    const verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return {
        success: false,
        error: 'Passkey registration verification failed',
        data: null
      };
    }

    // Store the credential in database
    const { registrationInfo } = verification;
    const credential = await prisma.webAuthnCredential.create({
      data: {
        userId: user.id,
        credentialId: bufferToBase64url(registrationInfo.credentialID),
        publicKey: bufferToBase64url(registrationInfo.credentialPublicKey),
        counter: registrationInfo.counter,
        name: credentialName || 'Passkey',
        createdAt: new Date(),
      }
    });

    return {
      success: true,
      error: null,
      data: { 
        credentialId: credential.credentialId,
        name: credential.name
      }
    };

  } catch (error) {
    console.error('Passkey registration verification error:', error);
    return {
      success: false,
      error: error?.message || 'Passkey registration failed',
      data: null
    };
  }
}

/**
 * Generate authentication options for passkey login
 * @param {string} [userEmail] - User email (optional for passwordless)
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function generatePasskeyAuthenticationOptions(userEmail = null) {
  try {
    let allowCredentials = [];

    if (userEmail) {
      // Get user's credentials for conditional UI
      const user = await prisma.user.findUnique({
        where: { email: userEmail.toLowerCase() },
        include: {
          webauthnCreds: {
            where: { id: { not: undefined } } // Only active credentials
          }
        }
      });

      if (user?.webauthnCreds) {
        allowCredentials = user.webauthnCreds.map(cred => ({
          id: cred.credentialId, // Keep as base64 string for SimpleWebAuthn
          type: 'public-key',
          // transports: cred.transports || [], // If you store transports
        }));
      }
    }

    const options = await generateAuthenticationOptions({
      timeout: parseInt(process.env.WEBAUTHN_AUTH_TIMEOUT_MS || '60000'),
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
      userVerification: 'preferred',
      rpID,
    });

    // Store challenge securely with automatic expiry
    const sessionId = generateSecureToken(16);
    const challengeResult = storeWebAuthnAuthenticationChallenge(sessionId, {
      challenge: options.challenge,
      userEmail,
      rpId: rpID
    });

    if (!challengeResult.success) {
      return {
        success: false,
        error: `Failed to store authentication challenge: ${challengeResult.error}`,
        data: null
      };
    }

    return {
      success: true,
      error: null,
      data: {
        ...options,
        sessionId // Return session ID so client can send it back
      }
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Failed to generate authentication options',
      data: null
    };
  }
}

/**
 * Verify passkey authentication response
 * @param {Object} authenticationResponse - WebAuthn authentication response
 * @param {string} sessionId - Session ID from authentication options
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function verifyPasskeyAuthentication(authenticationResponse, sessionId) {
  try {
    // Get stored challenge securely
    const challengeResult = retrieveWebAuthnAuthenticationChallenge(sessionId);
    
    if (!challengeResult.success) {
      return {
        success: false,
        error: `Authentication challenge error: ${challengeResult.error}`,
        data: null
      };
    }

    const storedChallenge = challengeResult.data;

    // Check timeout
    // TODO: CONFIGURATION - Make authentication challenge timeout configurable via environment variables
    const challengeTimeout = parseInt(process.env.WEBAUTHN_AUTH_TIMEOUT_MS || '120000'); // 2 minutes
    if (Date.now() - new Date(storedChallenge.timestamp).getTime() > challengeTimeout) {
      return {
        success: false,
        error: 'Authentication challenge has expired',
        data: null
      };
    }

    // Get credential from database
    const credential = await prisma.webAuthnCredential.findUnique({
      where: {
        credentialId: authenticationResponse.rawId
      },
      include: {
        user: true
      }
    });

    if (!credential) {
      return {
        success: false,
        error: 'Passkey not found',
        data: null
      };
    }

    // Verify the authentication response
    const verification = await verifyAuthenticationResponse({
      response: authenticationResponse,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: base64urlToBuffer(credential.credentialId),
        credentialPublicKey: base64urlToBuffer(credential.publicKey),
        counter: credential.counter,
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return {
        success: false,
        error: 'Passkey authentication verification failed',
        data: null
      };
    }

    // Update counter
    await prisma.webAuthnCredential.update({
      where: { id: credential.id },
      data: {
        counter: verification.authenticationInfo.newCounter,
        lastUsed: new Date()
      }
    });

    return {
      success: true,
      error: null,
      data: {
        user: credential.user,
        credentialId: credential.credentialId
      }
    };

  } catch (error) {
    console.error('Passkey authentication verification error:', error);
    return {
      success: false,
      error: error?.message || 'Passkey authentication failed',
      data: null
    };
  }
}

/**
 * Get user's passkeys
 * @param {string} userId - User ID
 * @returns {Promise<{success: boolean, error: string|null, data: Object[]|null}>}
 */
export async function getUserPasskeys(userId) {
  try {
    const credentials = await prisma.webAuthnCredential.findMany({
      where: { userId },
      select: {
        id: true,
        name: true,
        deviceType: true,
        createdAt: true,
        lastUsed: true
      },
      orderBy: { createdAt: 'desc' }
    });

    return {
      success: true,
      error: null,
      data: credentials
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Failed to fetch passkeys',
      data: null
    };
  }
}

/**
 * Delete a passkey
 * @param {string} userId - User ID
 * @param {string} credentialId - Credential ID to delete
 * @returns {Promise<{success: boolean, error: string|null}>}
 */
export async function deletePasskey(userId, credentialId) {
  try {
    await prisma.webAuthnCredential.deleteMany({
      where: {
        id: credentialId,
        userId: userId
      }
    });

    return {
      success: true,
      error: null
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Failed to delete passkey'
    };
  }
}

/**
 * Rename a passkey
 * @param {string} userId - User ID
 * @param {string} credentialId - Credential ID
 * @param {string} newName - New name for the passkey
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function renamePasskey(userId, credentialId, newName) {
  try {
    const credential = await prisma.webAuthnCredential.updateMany({
      where: {
        id: credentialId,
        userId: userId
      },
      data: {
        name: newName
      }
    });

    if (credential.count === 0) {
      return {
        success: false,
        error: 'Passkey not found',
        data: null
      };
    }

    return {
      success: true,
      error: null,
      data: { name: newName }
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Failed to rename passkey',
      data: null
    };
  }
}


