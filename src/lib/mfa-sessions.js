/**
 * Secure MFA Session Management
 * Replaces client-side sessionStorage with server-side secure sessions
 * @author IdP System
 */

import { db } from './database';
import { generateSecureToken } from './security';

/**
 * Create a secure MFA session
 * @param {string} userId - User ID requiring MFA
 * @param {string} userAgent - User agent string
 * @param {string} ipAddress - Client IP address
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export async function createMfaSession(userId, userAgent, ipAddress) {
  try {
    if (!userId) {
      return {
        success: false,
        error: 'User ID is required',
        data: null
      };
    }

    // Generate secure MFA session token
    const mfaToken = generateSecureToken(32);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store MFA session in database (secure server-side storage)
    const mfaSession = await db.mfaSession.create({
      data: {
        token: mfaToken,
        userId,
        userAgent: userAgent || 'Unknown',
        ipAddress: ipAddress || 'Unknown',
        expiresAt,
        isUsed: false,
        attempts: 0,
        maxAttempts: 5
      }
    });

    return {
      success: true,
      error: null,
      data: {
        mfaToken,
        expiresAt: mfaSession.expiresAt,
        sessionId: mfaSession.id
      }
    };

  } catch (error) {
    console.error('MFA session creation error:', error);
    return {
      success: false,
      error: 'Failed to create MFA session',
      data: null
    };
  }
}

/**
 * Validate MFA session token
 * @param {string} mfaToken - MFA session token
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export async function validateMfaSession(mfaToken) {
  try {
    if (!mfaToken) {
      return {
        success: false,
        error: 'MFA token is required',
        data: null
      };
    }

    // Find MFA session in database
    const mfaSession = await db.mfaSession.findFirst({
      where: {
        token: mfaToken,
        isUsed: false
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            username: true,
            mfaEnabled: true,
            totpSecret: true
          }
        }
      }
    });

    if (!mfaSession) {
      return {
        success: false,
        error: 'Invalid or expired MFA session',
        data: null
      };
    }

    // Check if session has expired
    if (new Date() > mfaSession.expiresAt) {
      // Clean up expired session
      await db.mfaSession.delete({
        where: { id: mfaSession.id }
      });

      return {
        success: false,
        error: 'MFA session expired',
        data: null
      };
    }

    // Check attempt limits
    if (mfaSession.attempts >= mfaSession.maxAttempts) {
      return {
        success: false,
        error: 'Too many MFA attempts',
        data: null
      };
    }

    return {
      success: true,
      error: null,
      data: {
        sessionId: mfaSession.id,
        userId: mfaSession.userId,
        user: mfaSession.user,
        attempts: mfaSession.attempts,
        maxAttempts: mfaSession.maxAttempts,
        expiresAt: mfaSession.expiresAt
      }
    };

  } catch (error) {
    console.error('MFA session validation error:', error);
    return {
      success: false,
      error: 'MFA session validation failed',
      data: null
    };
  }
}

/**
 * Increment MFA attempt counter
 * @param {string} mfaToken - MFA session token
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export async function incrementMfaAttempts(mfaToken) {
  try {
    const mfaSession = await db.mfaSession.findFirst({
      where: {
        token: mfaToken,
        isUsed: false
      }
    });

    if (!mfaSession) {
      return {
        success: false,
        error: 'MFA session not found',
        data: null
      };
    }

    // Increment attempts
    const updatedSession = await db.mfaSession.update({
      where: { id: mfaSession.id },
      data: {
        attempts: mfaSession.attempts + 1,
        lastAttemptAt: new Date()
      }
    });

    return {
      success: true,
      error: null,
      data: {
        attempts: updatedSession.attempts,
        maxAttempts: updatedSession.maxAttempts,
        remainingAttempts: updatedSession.maxAttempts - updatedSession.attempts
      }
    };

  } catch (error) {
    console.error('MFA attempt increment error:', error);
    return {
      success: false,
      error: 'Failed to update MFA attempts',
      data: null
    };
  }
}

/**
 * Complete MFA session (mark as used)
 * @param {string} mfaToken - MFA session token
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export async function completeMfaSession(mfaToken) {
  try {
    const mfaSession = await db.mfaSession.findFirst({
      where: {
        token: mfaToken,
        isUsed: false
      }
    });

    if (!mfaSession) {
      return {
        success: false,
        error: 'MFA session not found',
        data: null
      };
    }

    // Mark session as used
    await db.mfaSession.update({
      where: { id: mfaSession.id },
      data: {
        isUsed: true,
        completedAt: new Date()
      }
    });

    return {
      success: true,
      error: null,
      data: {
        sessionCompleted: true,
        userId: mfaSession.userId
      }
    };

  } catch (error) {
    console.error('MFA session completion error:', error);
    return {
      success: false,
      error: 'Failed to complete MFA session',
      data: null
    };
  }
}

/**
 * Clean up expired MFA sessions (maintenance function)
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export async function cleanupExpiredMfaSessions() {
  try {
    const result = await db.mfaSession.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { 
            createdAt: { 
              lt: new Date(Date.now() - 24 * 60 * 60 * 1000) // 24 hours old
            }
          }
        ]
      }
    });

    return {
      success: true,
      error: null,
      data: {
        deletedSessions: result.count
      }
    };

  } catch (error) {
    console.error('MFA session cleanup error:', error);
    return {
      success: false,
      error: 'Failed to cleanup MFA sessions',
      data: null
    };
  }
}

/**
 * Revoke all MFA sessions for a user
 * @param {string} userId - User ID
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export async function revokeMfaSessionsForUser(userId) {
  try {
    const result = await db.mfaSession.deleteMany({
      where: {
        userId,
        isUsed: false
      }
    });

    return {
      success: true,
      error: null,
      data: {
        revokedSessions: result.count
      }
    };

  } catch (error) {
    console.error('MFA session revocation error:', error);
    return {
      success: false,
      error: 'Failed to revoke MFA sessions',
      data: null
    };
  }
}
