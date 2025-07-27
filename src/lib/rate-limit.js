/**
 * Rate Limiting Utilities
 * Implements configurable rate limiting for authentication endpoints
 * @author IdP System
 */

// In-memory rate limiting store (in production, use Redis or similar)
const rateLimitStore = new Map();

/**
 * Rate limiting configuration
 */
const RATE_LIMIT_CONFIG = {
  // Login attempts per IP
  LOGIN_ATTEMPTS_PER_IP: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: parseInt(process.env.RATE_LIMIT_LOGIN_IP_MAX || '10'),
  },
  // Login attempts per email
  LOGIN_ATTEMPTS_PER_EMAIL: {
    windowMs: 5 * 60 * 1000, // 5 minutes  
    maxAttempts: parseInt(process.env.RATE_LIMIT_LOGIN_EMAIL_MAX || '5'),
  },
  // Registration attempts per IP
  REGISTRATION_ATTEMPTS_PER_IP: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxAttempts: parseInt(process.env.RATE_LIMIT_REGISTER_IP_MAX || '3'),
  },
  // Email verification attempts
  VERIFICATION_ATTEMPTS_PER_IP: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: parseInt(process.env.RATE_LIMIT_VERIFY_IP_MAX || '10'),
  }
};

/**
 * Create a rate limit key
 * @param {string} type - Type of rate limit (login_ip, login_email, etc.)
 * @param {string} identifier - IP address or email
 * @returns {string} Rate limit key
 */
function createRateLimitKey(type, identifier) {
  return `${type}:${identifier}`;
}

/**
 * Check if request is rate limited
 * @param {string} type - Type of rate limit
 * @param {string} identifier - IP address or email
 * @returns {{ success: boolean, error: string|null, data?: any }}
 */
export function checkRateLimit(type, identifier) {
  try {
    const config = RATE_LIMIT_CONFIG[type];
    if (!config) {
      return {
        success: false,
        error: 'Invalid rate limit type',
        data: null
      };
    }

    const key = createRateLimitKey(type, identifier);
    const now = Date.now();
    const windowStart = now - config.windowMs;

    // Get current attempts
    let attempts = rateLimitStore.get(key) || [];
    
    // Remove expired attempts
    attempts = attempts.filter(timestamp => timestamp > windowStart);
    
    // Check if limit exceeded
    if (attempts.length >= config.maxAttempts) {
      const oldestAttempt = Math.min(...attempts);
      const retryAfter = Math.ceil((oldestAttempt + config.windowMs - now) / 1000);
      
      return {
        success: false,
        error: `Rate limit exceeded. Try again in ${retryAfter} seconds.`,
        data: { retryAfter }
      };
    }

    return {
      success: true,
      error: null,
      data: { 
        remaining: config.maxAttempts - attempts.length,
        windowMs: config.windowMs
      }
    };
  } catch (error) {
    console.error('Rate limit check error:', error);
    return {
      success: false,
      error: 'Rate limit check failed',
      data: null
    };
  }
}

/**
 * Record a rate limit attempt
 * @param {string} type - Type of rate limit
 * @param {string} identifier - IP address or email
 * @returns {{ success: boolean, error: string|null }}
 */
export function recordRateLimitAttempt(type, identifier) {
  try {
    const key = createRateLimitKey(type, identifier);
    const now = Date.now();
    
    // Get current attempts
    let attempts = rateLimitStore.get(key) || [];
    
    // Add new attempt
    attempts.push(now);
    
    // Store updated attempts
    rateLimitStore.set(key, attempts);
    
    return {
      success: true,
      error: null
    };
  } catch (error) {
    console.error('Rate limit record error:', error);
    return {
      success: false,
      error: 'Failed to record rate limit attempt'
    };
  }
}

/**
 * Reset rate limit for identifier (useful after successful login)
 * @param {string} type - Type of rate limit
 * @param {string} identifier - IP address or email
 * @returns {{ success: boolean, error: string|null }}
 */
export function resetRateLimit(type, identifier) {
  try {
    const key = createRateLimitKey(type, identifier);
    rateLimitStore.delete(key);
    
    return {
      success: true,
      error: null
    };
  } catch (error) {
    console.error('Rate limit reset error:', error);
    return {
      success: false,
      error: 'Failed to reset rate limit'
    };
  }
}

/**
 * Get client IP address from request
 * @param {Request} request - Next.js request object
 * @returns {string} Client IP address
 */
export function getClientIP(request) {
  // Check various headers for the real IP
  const forwarded = request.headers.get('x-forwarded-for');
  const realIP = request.headers.get('x-real-ip');
  const cfConnectingIP = request.headers.get('cf-connecting-ip');
  
  if (forwarded) {
    // x-forwarded-for can contain multiple IPs, get the first one
    return forwarded.split(',')[0].trim();
  }
  
  if (realIP) {
    return realIP.trim();
  }
  
  if (cfConnectingIP) {
    return cfConnectingIP.trim();
  }
  
  // Fallback to localhost (for development)
  return '127.0.0.1';
}

/**
 * Cleanup expired rate limit entries (call periodically)
 */
export function cleanupExpiredRateLimits() {
  try {
    const now = Date.now();
    
    for (const [key, attempts] of rateLimitStore.entries()) {
      const type = key.split(':')[0];
      const config = RATE_LIMIT_CONFIG[type];
      
      if (config) {
        const windowStart = now - config.windowMs;
        const validAttempts = attempts.filter(timestamp => timestamp > windowStart);
        
        if (validAttempts.length === 0) {
          rateLimitStore.delete(key);
        } else if (validAttempts.length !== attempts.length) {
          rateLimitStore.set(key, validAttempts);
        }
      }
    }
    
    return {
      success: true,
      error: null
    };
  } catch (error) {
    console.error('Rate limit cleanup error:', error);
    return {
      success: false,
      error: 'Rate limit cleanup failed'
    };
  }
}

// Cleanup expired entries every 5 minutes
if (typeof global !== 'undefined') {
  setInterval(cleanupExpiredRateLimits, 5 * 60 * 1000);
}
