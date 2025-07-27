/**
 * Core authentication utility functions
 * Handles password hashing, token generation, and security operations
 * @author IdP System
 */

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

/**
 * Hash a password using bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<{success: boolean, error: string|null, data: string}>}
 */
export async function hashPassword(password) {
  try {
    // TODO: SECURITY-Important - parseInt without radix can cause issues with leading zeros or hex values
    const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    const hashedPassword = await bcrypt.hash(password, rounds);
    
    return {
      success: true,
      error: null,
      data: hashedPassword
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Password hashing failed',
      data: null
    };
  }
}

/**
 * Verify a password against its hash
 * @param {string} password - Plain text password
 * @param {string} hash - Hashed password
 * @returns {Promise<{success: boolean, error: string|null, data: boolean}>}
 */
export async function verifyPassword(password, hash) {
  try {
    const isValid = await bcrypt.compare(password, hash);
    
    return {
      success: true,
      error: null,
      data: isValid
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Password verification failed',
      data: false
    };
  }
}

/**
 * Generate a JWT access token
 * @param {Object} payload - Token payload
 * @param {string} [expiresIn='15m'] - Token expiration
 * @returns {Promise<{success: boolean, error: string|null, data: string}>}
 */
export async function generateAccessToken(payload, expiresIn = '15m') {
  try {
    // TODO: SECURITY - Add startup validation for JWT_SECRET instead of runtime check
    // TODO: SECURITY - Consider rotating JWT secrets and key versioning
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return {
        success: false,
        error: 'JWT secret not configured',
        data: null
      };
    }

    const token = jwt.sign(payload, secret, { expiresIn });
    
    return {
      success: true,
      error: null,
      data: token
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Token generation failed',
      data: null
    };
  }
}

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token
 * @returns {Promise<{success: boolean, error: string|null, data: Object}>}
 */
export async function verifyAccessToken(token) {
  try {
    // TODO: SECURITY - Add startup validation for JWT_SECRET instead of runtime check
    // TODO: SECURITY - Implement token blacklisting for logout/revocation
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      return {
        success: false,
        error: 'JWT secret not configured',
        data: null
      };
    }

    const decoded = jwt.verify(token, secret);
    
    return {
      success: true,
      error: null,
      data: decoded
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Token verification failed',
      data: null
    };
  }
}

/**
 * Generate a secure random token
 * @param {number} [length=32] - Token length in bytes
 * @returns {string} - Hex encoded token
 */
export function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate a secure random string for various purposes
 * @param {number} [length=16] - String length
 * @returns {string} - Random string
 */
export function generateRandomString(length = 16) {
  // TODO: SECURITY - Replace Math.random() with crypto.getRandomValues() for cryptographic security
  // TODO: PERFORMANCE - Consider using crypto.randomBytes instead for better performance
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

/**
 * Create a secure hash for device fingerprinting
 * @param {string} data - Data to hash
 * @returns {string} - SHA256 hash
 */
export function createSecureHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Validate email format
 * @param {string} email - Email address
 * @returns {boolean} - Is valid email
 */
export function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {{isValid: boolean, errors: string[]}} - Validation result
 */
export function validatePassword(password) {
  // TODO: SECURITY - Add check against common password lists (rockyou.txt, etc.)
  // TODO: SECURITY - Add password history check to prevent reuse
  // TODO: SECURITY - Calculate password entropy score
  // TODO: SECURITY - Add check for keyboard patterns (qwerty, 123456, etc.)
  const errors = [];
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}
