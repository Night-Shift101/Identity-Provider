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

// WebAuthn configuration
const rpName = process.env.APP_NAME || 'Identity Provider';
const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';
// TODO: SECURITY-Critical - Move to environment variable configuration
const origin = process.env.APP_URL || 'http://localhost:3000';

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
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: excludeCredentialsList,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform', // Prefer platform authenticators (Face ID, Touch ID, Windows Hello)
      },
      supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
    });

    // Store challenge temporarily (in production, use Redis or similar)
    // TODO: SECURITY - CRITICAL: Replace global memory with Redis/secure storage
    // TODO: SECURITY - Add challenge expiry and cleanup mechanism
    // TODO: PERFORMANCE - This will cause memory leaks and race conditions in production
    if (!global.webauthnChallenges) {
      global.webauthnChallenges = new Map();
    }
    
    const challengeKey = `${user.id}_registration`;
    global.webauthnChallenges.set(challengeKey, {
      challenge: options.challenge,
      timestamp: Date.now()
    });

    // Clean up old challenges (older than 5 minutes)
    cleanupOldChallenges();

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
    // Get stored challenge
    const challengeKey = `${user.id}_registration`;
    const storedChallenge = global.webauthnChallenges?.get(challengeKey);
    
    if (!storedChallenge) {
      return {
        success: false,
        error: 'No registration challenge found',
        data: null
      };
    }

    // Check challenge age (5 minutes max)
    // TODO: CONFIGURATION - Make challenge timeout configurable via environment variables
    if (Date.now() - storedChallenge.timestamp > 5 * 60 * 1000) {
      global.webauthnChallenges.delete(challengeKey);
      return {
        success: false,
        error: 'Registration challenge expired',
        data: null
      };
    }

    const verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    // Clean up challenge
    global.webauthnChallenges.delete(challengeKey);

    if (!verification.verified) {
      return {
        success: false,
        error: 'Registration verification failed',
        data: null
      };
    }

    const { registrationInfo } = verification;

    // Store credential in database
    const credential = await prisma.webAuthnCredential.create({
      data: {
        userId: user.id,
        credentialId: bufferToBase64url(registrationInfo.credentialID),
        publicKey: Buffer.from(registrationInfo.credentialPublicKey).toString('base64'),
        counter: registrationInfo.counter,
        deviceType: registrationInfo.credentialDeviceType,
        name: credentialName || 'Unnamed Passkey',
        createdAt: new Date(),
      }
    });

    return {
      success: true,
      error: null,
      data: {
        credential: {
          id: credential.id,
          credentialId: credential.credentialId,
          name: credential.name,
          deviceType: credential.deviceType,
          createdAt: credential.createdAt
        },
        verified: true
      }
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Registration verification failed',
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
      timeout: 60000,
      allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
      userVerification: 'preferred',
      rpID,
    });

    // Store challenge temporarily
    if (!global.webauthnChallenges) {
      global.webauthnChallenges = new Map();
    }
    
    const challengeKey = `auth_${generateSecureToken(16)}`;
    global.webauthnChallenges.set(challengeKey, {
      challenge: options.challenge,
      timestamp: Date.now(),
      userEmail
    });

    // Clean up old challenges
    cleanupOldChallenges();

    return {
      success: true,
      error: null,
      data: {
        options,
        challengeKey
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
 * @param {string} challengeKey - Challenge key from registration
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function verifyPasskeyAuthentication(authenticationResponse, challengeKey) {
  try {
    // Get stored challenge
    const storedChallenge = global.webauthnChallenges?.get(challengeKey);
    
    if (!storedChallenge) {
      return {
        success: false,
        error: 'No authentication challenge found',
        data: null
      };
    }

    // Check challenge age (5 minutes max)
    // TODO: CONFIGURATION - Make authentication challenge timeout configurable via environment variables
    if (Date.now() - storedChallenge.timestamp > 5 * 60 * 1000) {
      global.webauthnChallenges.delete(challengeKey);
      return {
        success: false,
        error: 'Authentication challenge expired',
        data: null
      };
    }

    // Find credential
    const credential = await prisma.webAuthnCredential.findUnique({
      where: { credentialId: authenticationResponse.id },
      include: { user: true }
    });

    if (!credential) {
      return {
        success: false,
        error: 'Credential not found',
        data: null
      };
    }

    const verification = await verifyAuthenticationResponse({
      response: authenticationResponse,
      expectedChallenge: storedChallenge.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: base64urlToBuffer(credential.credentialId),
        credentialPublicKey: Buffer.from(credential.publicKey, 'base64'),
        counter: credential.counter,
      },
      requireUserVerification: true,
    });

    // Clean up challenge
    global.webauthnChallenges.delete(challengeKey);

    if (!verification.verified) {
      return {
        success: false,
        error: 'Authentication verification failed',
        data: null
      };
    }

    // Update credential counter
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
        credential: {
          id: credential.id,
          name: credential.name,
          lastUsed: new Date()
        },
        verified: true
      }
    };

  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Authentication verification failed',
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

/**
 * Clean up old challenges
 */
function cleanupOldChallenges() {
  // TODO: SECURITY - Implement proper challenge cleanup with configurable TTL
  // TODO: PERFORMANCE - Add scheduled cleanup instead of on-demand
  // TODO: BUG - This cleanup runs on every registration, inefficient
  if (!global.webauthnChallenges) return;
  
  const now = Date.now();
  const fiveMinutesAgo = now - 5 * 60 * 1000;
  
  for (const [key, challenge] of global.webauthnChallenges.entries()) {
    if (challenge.timestamp < fiveMinutesAgo) {
      global.webauthnChallenges.delete(key);
    }
  }
}
