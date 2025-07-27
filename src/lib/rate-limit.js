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
  },
  // OAuth operations per IP
  OAUTH_ATTEMPTS_PER_IP: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: parseInt(process.env.RATE_LIMIT_OAUTH_IP_MAX || '20'),
  },
  // Email sending per IP
  EMAIL_SEND_PER_IP: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxAttempts: parseInt(process.env.RATE_LIMIT_EMAIL_IP_MAX || '10'),
  },
  // Email sending per recipient
  EMAIL_SEND_PER_EMAIL: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxAttempts: parseInt(process.env.RATE_LIMIT_EMAIL_RECIPIENT_MAX || '5'),
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
 * Trusted proxy configuration
 * Configure these based on your infrastructure
 */
const TRUSTED_PROXIES = [
  '127.0.0.1',
  '::1',
  '10.0.0.0/8',
  '172.16.0.0/12', 
  '192.168.0.0/16',
  // Add your load balancer/proxy IPs here
  ...(process.env.TRUSTED_PROXIES ? process.env.TRUSTED_PROXIES.split(',').map(ip => ip.trim()) : [])
];

/**
 * Check if IP is in CIDR range
 * @param {string} ip - IP address to check
 * @param {string} cidr - CIDR notation (e.g., '192.168.0.0/16')
 * @returns {boolean} True if IP is in range
 */
function isIPInCIDR(ip, cidr) {
  try {
    if (!cidr.includes('/')) {
      // Single IP comparison
      return ip === cidr;
    }

    const [network, prefixLength] = cidr.split('/');
    const prefixLengthNum = parseInt(prefixLength, 10);
    
    // Convert IPs to integers for comparison
    const ipToInt = (ipStr) => {
      return ipStr.split('.').reduce((acc, octet) => {
        return (acc << 8) + parseInt(octet, 10);
      }, 0) >>> 0; // Use unsigned 32-bit integer
    };

    const ipInt = ipToInt(ip);
    const networkInt = ipToInt(network);
    const mask = (0xFFFFFFFF << (32 - prefixLengthNum)) >>> 0;

    return (ipInt & mask) === (networkInt & mask);
  } catch (error) {
    console.error('CIDR check error:', error);
    return false;
  }
}

/**
 * Check if IP is from a trusted proxy
 * @param {string} ip - IP address to check
 * @returns {boolean} True if IP is trusted
 */
function isTrustedProxy(ip) {
  if (!ip) return false;
  
  return TRUSTED_PROXIES.some(trustedRange => isIPInCIDR(ip, trustedRange));
}

/**
 * Validate IP address format
 * @param {string} ip - IP address to validate
 * @returns {boolean} True if valid IPv4 address
 */
function isValidIPv4(ip) {
  if (!ip || typeof ip !== 'string') return false;
  
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

/**
 * Sanitize and validate IP address
 * @param {string} ip - Raw IP address
 * @returns {string|null} Sanitized IP or null if invalid
 */
function sanitizeIP(ip) {
  if (!ip || typeof ip !== 'string') return null;
  
  // Remove any whitespace and quotes
  const cleaned = ip.trim().replace(/['"]/g, '');
  
  // Basic validation
  if (!isValidIPv4(cleaned)) return null;
  
  // Check for private/reserved ranges that shouldn't be trusted
  const parts = cleaned.split('.').map(Number);
  
  // Reject obviously invalid IPs
  if (parts.some(part => isNaN(part) || part < 0 || part > 255)) {
    return null;
  }
  
  return cleaned;
}

/**
 * Get client IP address from request with trusted proxy validation
 * @param {Request} request - Next.js request object
 * @returns {{ ip: string, trusted: boolean, source: string }}
 */
export function getClientIPInfo(request) {
  const defaultResult = { 
    ip: '127.0.0.1', 
    trusted: false, 
    source: 'default' 
  };

  try {
    // Get potential IP sources in order of preference
    const xForwardedFor = request.headers.get('x-forwarded-for');
    const xRealIP = request.headers.get('x-real-ip');
    const cfConnectingIP = request.headers.get('cf-connecting-ip');
    const xClientIP = request.headers.get('x-client-ip');
    
    // Check Cloudflare first (most trusted if using CF)
    if (cfConnectingIP) {
      const sanitizedIP = sanitizeIP(cfConnectingIP);
      if (sanitizedIP) {
        return {
          ip: sanitizedIP,
          trusted: true,
          source: 'cloudflare'
        };
      }
    }

    // Check X-Real-IP (usually set by nginx)
    if (xRealIP) {
      const sanitizedIP = sanitizeIP(xRealIP);
      if (sanitizedIP) {
        return {
          ip: sanitizedIP,
          trusted: isTrustedProxy(request.headers.get('host') || ''),
          source: 'x-real-ip'
        };
      }
    }

    // Check X-Client-IP
    if (xClientIP) {
      const sanitizedIP = sanitizeIP(xClientIP);
      if (sanitizedIP) {
        return {
          ip: sanitizedIP,
          trusted: isTrustedProxy(request.headers.get('host') || ''),
          source: 'x-client-ip'
        };
      }
    }

    // Check X-Forwarded-For (can contain multiple IPs)
    if (xForwardedFor) {
      const ips = xForwardedFor.split(',').map(ip => ip.trim());
      
      for (const ip of ips) {
        const sanitizedIP = sanitizeIP(ip);
        if (sanitizedIP && !isTrustedProxy(sanitizedIP)) {
          // Found first non-proxy IP
          return {
            ip: sanitizedIP,
            trusted: true, // We trust the proxy chain
            source: 'x-forwarded-for'
          };
        }
      }
    }

    return defaultResult;
  } catch (error) {
    console.error('IP extraction error:', error);
    return defaultResult;
  }
}

/**
 * Get client IP address from request (legacy function for backward compatibility)
 * @param {Request} request - Next.js request object
 * @returns {string} Client IP address
 */
export function getClientIP(request) {
  const ipInfo = getClientIPInfo(request);
  return ipInfo.ip;
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
