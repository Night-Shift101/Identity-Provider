/**
 * Secure challenge storage utilities for WebAuthn and other cryptographic challenges
 * Implements secure temporary storage with automatic expiry and cleanup
 * @author IdP System
 */

import crypto from 'crypto';
import { isProduction } from '@/lib/config-validation';

// In-memory challenge store (in production, replace with Redis or similar secure storage)
const challengeStore = new Map();

/**
 * Challenge storage configuration
 */
const CHALLENGE_CONFIG = {
  // WebAuthn registration challenge TTL
  WEBAUTHN_REGISTRATION: {
    ttlMs: parseInt(process.env.WEBAUTHN_CHALLENGE_TTL_MS || '300000'), // 5 minutes
    cleanupIntervalMs: parseInt(process.env.CHALLENGE_CLEANUP_INTERVAL_MS || '60000'), // 1 minute
  },
  // WebAuthn authentication challenge TTL
  WEBAUTHN_AUTHENTICATION: {
    ttlMs: parseInt(process.env.WEBAUTHN_AUTH_TTL_MS || '120000'), // 2 minutes
    cleanupIntervalMs: parseInt(process.env.CHALLENGE_CLEANUP_INTERVAL_MS || '60000'), // 1 minute
  },
  // General challenge TTL (for other use cases)
  GENERAL: {
    ttlMs: parseInt(process.env.GENERAL_CHALLENGE_TTL_MS || '300000'), // 5 minutes
    cleanupIntervalMs: parseInt(process.env.CHALLENGE_CLEANUP_INTERVAL_MS || '60000'), // 1 minute
  }
};

/**
 * Generate a cryptographically secure challenge key
 * @param {string} prefix - Key prefix for identification
 * @param {string} identifier - Unique identifier (user ID, session ID, etc.)
 * @returns {string} Secure challenge key
 */
function generateChallengeKey(prefix, identifier) {
  // Use cryptographic hashing to prevent key manipulation
  const hash = crypto.createHash('sha256');
  hash.update(`${prefix}:${identifier}:${Date.now()}`);
  return `${prefix}_${hash.digest('hex').substring(0, 16)}`;
}

/**
 * Store a challenge securely with automatic expiry
 * @param {string} type - Challenge type (WEBAUTHN_REGISTRATION, WEBAUTHN_AUTHENTICATION, GENERAL)
 * @param {string} identifier - Unique identifier (user ID, session ID, etc.)
 * @param {any} challengeData - Challenge data to store
 * @param {number} [customTtlMs] - Custom TTL in milliseconds (overrides config)
 * @returns {{ success: boolean, error: string|null, data?: { key: string, expiresAt: Date } }}
 */
export function storeChallenge(type, identifier, challengeData, customTtlMs = null) {
  try {
    if (!type || !identifier || challengeData === undefined) {
      return {
        success: false,
        error: 'Missing required parameters: type, identifier, or challengeData',
        data: null
      };
    }

    // Validate challenge type
    if (!CHALLENGE_CONFIG[type]) {
      return {
        success: false,
        error: `Invalid challenge type: ${type}`,
        data: null
      };
    }

    const config = CHALLENGE_CONFIG[type];
    const ttl = customTtlMs || config.ttlMs;
    const expiresAt = new Date(Date.now() + ttl);
    
    // Generate secure key
    const key = generateChallengeKey(type.toLowerCase(), identifier);
    
    // Store challenge with metadata
    challengeStore.set(key, {
      data: challengeData,
      identifier,
      type,
      createdAt: new Date(),
      expiresAt,
      accessed: false
    });

    // Schedule cleanup if we're in production (prevent memory leaks)
    if (isProduction()) {
      setTimeout(() => {
        challengeStore.delete(key);
      }, ttl + 5000); // Add 5 second buffer
    }

    return {
      success: true,
      error: null,
      data: { key, expiresAt }
    };

  } catch (error) {
    console.error('Challenge storage error:', error);
    return {
      success: false,
      error: 'Failed to store challenge',
      data: null
    };
  }
}

/**
 * Retrieve and optionally consume a challenge
 * @param {string} key - Challenge key
 * @param {boolean} [consume=true] - Whether to delete the challenge after retrieval
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export function retrieveChallenge(key, consume = true) {
  try {
    if (!key) {
      return {
        success: false,
        error: 'Challenge key is required',
        data: null
      };
    }

    const storedChallenge = challengeStore.get(key);
    
    if (!storedChallenge) {
      return {
        success: false,
        error: 'Challenge not found or expired',
        data: null
      };
    }

    // Check expiry
    if (new Date() > storedChallenge.expiresAt) {
      challengeStore.delete(key);
      return {
        success: false,
        error: 'Challenge has expired',
        data: null
      };
    }

    // Mark as accessed (for analytics/monitoring)
    storedChallenge.accessed = true;
    storedChallenge.accessedAt = new Date();

    // Consume challenge if requested
    if (consume) {
      challengeStore.delete(key);
    } else {
      challengeStore.set(key, storedChallenge);
    }

    return {
      success: true,
      error: null,
      data: storedChallenge.data
    };

  } catch (error) {
    console.error('Challenge retrieval error:', error);
    return {
      success: false,
      error: 'Failed to retrieve challenge',
      data: null
    };
  }
}

/**
 * Delete a specific challenge
 * @param {string} key - Challenge key
 * @returns {{ success: boolean, error: string|null }}
 */
export function deleteChallenge(key) {
  try {
    if (!key) {
      return {
        success: false,
        error: 'Challenge key is required'
      };
    }

    const existed = challengeStore.delete(key);
    
    return {
      success: true,
      error: null,
      data: { deleted: existed }
    };

  } catch (error) {
    console.error('Challenge deletion error:', error);
    return {
      success: false,
      error: 'Failed to delete challenge'
    };
  }
}

/**
 * Clean up expired challenges
 * @param {string} [type] - Optional: only clean challenges of specific type
 * @returns {{ success: boolean, error: string|null, data?: { cleaned: number } }}
 */
export function cleanupExpiredChallenges(type = null) {
  try {
    let cleanedCount = 0;
    const now = new Date();

    for (const [key, challenge] of challengeStore.entries()) {
      // Filter by type if specified
      if (type && challenge.type !== type) {
        continue;
      }

      // Delete expired challenges
      if (now > challenge.expiresAt) {
        challengeStore.delete(key);
        cleanedCount++;
      }
    }

    return {
      success: true,
      error: null,
      data: { cleaned: cleanedCount }
    };

  } catch (error) {
    console.error('Challenge cleanup error:', error);
    return {
      success: false,
      error: 'Failed to cleanup expired challenges',
      data: { cleaned: 0 }
    };
  }
}

/**
 * Get challenge storage statistics (for monitoring)
 * @returns {{ success: boolean, error: string|null, data?: Object }}
 */
export function getChallengeStats() {
  try {
    const stats = {
      totalChallenges: challengeStore.size,
      byType: {},
      expired: 0,
      accessed: 0
    };

    const now = new Date();

    for (const [key, challenge] of challengeStore.entries()) {
      // Count by type
      if (!stats.byType[challenge.type]) {
        stats.byType[challenge.type] = 0;
      }
      stats.byType[challenge.type]++;

      // Count expired
      if (now > challenge.expiresAt) {
        stats.expired++;
      }

      // Count accessed
      if (challenge.accessed) {
        stats.accessed++;
      }
    }

    return {
      success: true,
      error: null,
      data: stats
    };

  } catch (error) {
    console.error('Challenge stats error:', error);
    return {
      success: false,
      error: 'Failed to get challenge statistics',
      data: null
    };
  }
}

/**
 * Clear all challenges (for testing or emergency cleanup)
 * @param {string} [type] - Optional: only clear challenges of specific type
 * @returns {{ success: boolean, error: string|null, data?: { cleared: number } }}
 */
export function clearChallenges(type = null) {
  try {
    let clearedCount = 0;

    if (type) {
      // Clear only specific type
      for (const [key, challenge] of challengeStore.entries()) {
        if (challenge.type === type) {
          challengeStore.delete(key);
          clearedCount++;
        }
      }
    } else {
      // Clear all
      clearedCount = challengeStore.size;
      challengeStore.clear();
    }

    return {
      success: true,
      error: null,
      data: { cleared: clearedCount }
    };

  } catch (error) {
    console.error('Challenge clear error:', error);
    return {
      success: false,
      error: 'Failed to clear challenges',
      data: { cleared: 0 }
    };
  }
}

// Automatic cleanup interval (run every minute by default)
let cleanupInterval = null;

/**
 * Start automatic cleanup of expired challenges
 * @param {number} [intervalMs] - Cleanup interval in milliseconds
 */
export function startAutomaticCleanup(intervalMs = CHALLENGE_CONFIG.GENERAL.cleanupIntervalMs) {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
  }

  cleanupInterval = setInterval(() => {
    const result = cleanupExpiredChallenges();
    if (result.success && result.data.cleaned > 0) {
      console.log(`Cleaned up ${result.data.cleaned} expired challenges`);
    }
  }, intervalMs);

  console.log(`Started automatic challenge cleanup with ${intervalMs}ms interval`);
}

/**
 * Stop automatic cleanup
 */
export function stopAutomaticCleanup() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log('Stopped automatic challenge cleanup');
  }
}

// Start automatic cleanup when module loads (only in production)
if (isProduction()) {
  startAutomaticCleanup();
}

// Helper function for WebAuthn registration challenges
export function storeWebAuthnRegistrationChallenge(userId, challengeData) {
  return storeChallenge('WEBAUTHN_REGISTRATION', userId, challengeData);
}

// Helper function for WebAuthn authentication challenges
export function storeWebAuthnAuthenticationChallenge(userId, challengeData) {
  return storeChallenge('WEBAUTHN_AUTHENTICATION', userId, challengeData);
}

// Helper function to retrieve WebAuthn registration challenge
export function retrieveWebAuthnRegistrationChallenge(userId) {
  // We need to find the challenge by userId since we don't have the key
  // This is a limitation of the current approach - in production, use a proper key-value store
  for (const [key, challenge] of challengeStore.entries()) {
    if (challenge.type === 'WEBAUTHN_REGISTRATION' && challenge.identifier === userId) {
      return retrieveChallenge(key, true);
    }
  }
  
  return {
    success: false,
    error: 'Registration challenge not found',
    data: null
  };
}

// Helper function to retrieve WebAuthn authentication challenge
export function retrieveWebAuthnAuthenticationChallenge(userId) {
  // We need to find the challenge by userId since we don't have the key
  // This is a limitation of the current approach - in production, use a proper key-value store
  for (const [key, challenge] of challengeStore.entries()) {
    if (challenge.type === 'WEBAUTHN_AUTHENTICATION' && challenge.identifier === userId) {
      return retrieveChallenge(key, true);
    }
  }
  
  return {
    success: false,
    error: 'Authentication challenge not found',
    data: null
  };
}
