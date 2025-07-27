/**
 * Database utilities and Prisma client configuration
 * Provides centralized database access with connection management
 * @author IdP System
 */

// TODO: INFRASTRUCTURE - Implement database backup and disaster recovery procedures
import { PrismaClient } from '@prisma/client';

// Global Prisma instance to prevent multiple connections in development
const globalForPrisma = globalThis;

/**
 * Prisma client instance with proper configuration
 */
// TODO: SECURITY - Add connection pooling limits and timeout configuration
// TODO: PERFORMANCE - Implement connection retry logic and circuit breaker
// TODO: MONITORING - Add database connection monitoring and alerts
export const prisma = globalForPrisma.prisma || new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
});

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

/**
 * Gracefully disconnect from database
 * @returns {Promise<{success: boolean, error: string|null}>}
 */
export async function disconnectDatabase() {
  try {
    await prisma.$disconnect();
    return {
      success: true,
      error: null
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Database disconnection failed'
    };
  }
}

/**
 * Test database connection
 * @returns {Promise<{success: boolean, error: string|null, data?: Object}>}
 */
export async function testDatabaseConnection() {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return {
      success: true,
      error: null,
      data: { status: 'connected' }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Database connection failed',
      data: null
    };
  }
}

/**
 * User database operations
 */
export const userDb = {
  /**
   * Create a new user
   * @param {Object} userData - User data
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async create(userData) {
    try {
      const user = await prisma.user.create({
        data: userData,
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
          isActive: true,
          isVerified: true,
          createdAt: true
        }
      });

      return {
        success: true,
        error: null,
        data: user
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'User creation failed',
        data: null
      };
    }
  },

  /**
   * Find user by email
   * @param {string} email - User email
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async findByEmail(email) {
    try {
      const user = await prisma.user.findUnique({
        where: { email },
        include: {
          trustedDevices: true,
          oauthAccounts: true
        }
      });

      return {
        success: true,
        error: null,
        data: user
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'User lookup failed',
        data: null
      };
    }
  },

  /**
   * Find user by ID
   * @param {string} id - User ID
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async findById(id) {
    try {
      const user = await prisma.user.findUnique({
        where: { id },
        include: {
          trustedDevices: true,
          oauthAccounts: true,
          webauthnCreds: true
        }
      });

      return {
        success: true,
        error: null,
        data: user
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'User lookup failed',
        data: null
      };
    }
  },

  /**
   * Update user data
   * @param {string} id - User ID
   * @param {Object} updateData - Data to update
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async update(id, updateData) {
    try {
      const user = await prisma.user.update({
        where: { id },
        data: updateData,
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
          isActive: true,
          isVerified: true,
          mfaEnabled: true,
          updatedAt: true
        }
      });

      return {
        success: true,
        error: null,
        data: user
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'User update failed',
        data: null
      };
    }
  },

  /**
   * Update user password
   * @param {string} userId - User ID
   * @param {string} hashedPassword - New hashed password
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async updatePassword(userId, hashedPassword) {
    try {
      const user = await prisma.user.update({
        where: { id: userId },
        data: { 
          password: hashedPassword,
          updatedAt: new Date()
        },
        select: {
          id: true,
          email: true,
          updatedAt: true
        }
      });

      return {
        success: true,
        error: null,
        data: user
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Password update failed',
        data: null
      };
    }
  }
};

/**
 * Session database operations
 */
export const sessionDb = {
  /**
   * Create a new session
   * @param {Object} sessionData - Session data
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async create(sessionData) {
    try {
      const session = await prisma.session.create({
        data: sessionData
      });

      return {
        success: true,
        error: null,
        data: session
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Session creation failed',
        data: null
      };
    }
  },

  /**
   * Find session by token
   * @param {string} sessionToken - Session token
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async findByToken(sessionToken) {
    try {
      const session = await prisma.session.findUnique({
        where: { sessionToken },
        include: {
          user: {
            select: {
              id: true,
              email: true,
              username: true,
              firstName: true,
              lastName: true,
              isActive: true,
              isVerified: true,
              mfaEnabled: true
            }
          }
        }
      });

      return {
        success: true,
        error: null,
        data: session
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Session lookup failed',
        data: null
      };
    }
  },

  /**
   * Delete session
   * @param {string} sessionToken - Session token
   * @returns {Promise<{success: boolean, error: string|null}>}
   */
  async delete(sessionToken) {
    try {
      await prisma.session.delete({
        where: { sessionToken }
      });

      return {
        success: true,
        error: null
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Session deletion failed'
      };
    }
  },

  /**
   * Delete all sessions for a user
   * @param {string} userId - User ID
   * @returns {Promise<{success: boolean, error: string|null}>}
   */
  async deleteAllForUser(userId) {
    try {
      await prisma.session.deleteMany({
        where: { userId }
      });

      return {
        success: true,
        error: null
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Sessions deletion failed'
      };
    }
  }
};

/**
 * Activity logging operations
 */
export const activityDb = {
  /**
   * Log login activity
   * @param {Object} activityData - Activity data
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async logActivity(activityData) {
    try {
      const activity = await prisma.loginActivity.create({
        data: activityData
      });

      return {
        success: true,
        error: null,
        data: activity
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Activity logging failed',
        data: null
      };
    }
  },

  /**
   * Get recent activity for user
   * @param {string} userId - User ID
   * @param {number} [limit=10] - Number of records to return
   * @returns {Promise<{success: boolean, error: string|null, data: Object[]|null}>}
   */
  async getRecentActivity(userId, limit = 10) {
    try {
      const activities = await prisma.loginActivity.findMany({
        where: { userId },
        orderBy: { timestamp: 'desc' },
        take: limit
      });

      return {
        success: true,
        error: null,
        data: activities
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Activity lookup failed',
        data: null
      };
    }
  }
};

/**
 * Password History Database Operations
 * Manages password history for security compliance
 */
export const passwordHistoryDb = {
  /**
   * Add password to history
   * @param {string} userId - User ID
   * @param {string} passwordHash - Password hash for comparison
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async addPasswordToHistory(userId, passwordHash) {
    try {
      const historyEntry = await prisma.passwordHistory.create({
        data: {
          userId,
          passwordHash,
          createdAt: new Date()
        }
      });

      return {
        success: true,
        error: null,
        data: historyEntry
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Failed to add password to history',
        data: null
      };
    }
  },

  /**
   * Get user password history
   * @param {string} userId - User ID
   * @param {number} limit - Number of recent passwords to retrieve (default: 10)
   * @returns {Promise<{success: boolean, error: string|null, data: Array}>}
   */
  async getUserPasswordHistory(userId, limit = 10) {
    try {
      const history = await prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: limit,
        select: {
          passwordHash: true,
          createdAt: true
        }
      });

      return {
        success: true,
        error: null,
        data: history
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Failed to retrieve password history',
        data: null
      };
    }
  },

  /**
   * Clean old password history entries
   * @param {string} userId - User ID
   * @param {number} keepCount - Number of recent passwords to keep (default: 10)
   * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
   */
  async cleanOldPasswordHistory(userId, keepCount = 10) {
    try {
      // Get IDs of entries to keep
      const recentEntries = await prisma.passwordHistory.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        take: keepCount,
        select: { id: true }
      });

      const idsToKeep = recentEntries.map(entry => entry.id);

      // Delete older entries
      const deleteResult = await prisma.passwordHistory.deleteMany({
        where: {
          userId,
          id: {
            notIn: idsToKeep
          }
        }
      });

      return {
        success: true,
        error: null,
        data: { deletedCount: deleteResult.count }
      };
    } catch (err) {
      return {
        success: false,
        error: err?.message || 'Failed to clean password history',
        data: null
      };
    }
  }
};

export default prisma;
