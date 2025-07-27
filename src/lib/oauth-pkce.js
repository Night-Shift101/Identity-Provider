/**
 * OAuth PKCE (Proof Key for Code Exchange) Utilities
 * Implements RFC 7636 PKCE for OAuth2 security enhancement
 * @author IdP System
 */

import crypto from 'crypto';

/**
 * Generate a cryptographically secure random string for PKCE
 * @param {number} length - Length of the string (43-128 characters per RFC)
 * @returns {string} Base64url-encoded string
 */
export function generateCodeVerifier(length = 128) {
  if (length < 43 || length > 128) {
    throw new Error('Code verifier length must be between 43 and 128 characters');
  }
  
  // Generate random bytes and convert to base64url
  const buffer = crypto.randomBytes(Math.ceil(length * 3 / 4));
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
    .substring(0, length);
}

/**
 * Generate code challenge from code verifier using S256 method
 * @param {string} codeVerifier - The code verifier string
 * @returns {string} Base64url-encoded SHA256 hash of code verifier
 */
export function generateCodeChallenge(codeVerifier) {
  if (!codeVerifier || typeof codeVerifier !== 'string') {
    throw new Error('Code verifier must be a non-empty string');
  }
  
  // Create SHA256 hash of code verifier
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  
  // Convert to base64url
  return hash
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate complete PKCE parameters
 * @returns {{ codeVerifier: string, codeChallenge: string, codeChallengeMethod: string }}
 */
export function generatePKCEParams() {
  try {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256'
    };
  } catch (error) {
    console.error('PKCE generation error:', error);
    throw new Error('Failed to generate PKCE parameters');
  }
}

/**
 * Verify PKCE code verifier against stored challenge
 * @param {string} codeVerifier - Code verifier from client
 * @param {string} storedCodeChallenge - Stored code challenge
 * @param {string} method - Challenge method (should be 'S256')
 * @returns {boolean} True if verification succeeds
 */
export function verifyPKCE(codeVerifier, storedCodeChallenge, method = 'S256') {
  try {
    if (!codeVerifier || !storedCodeChallenge) {
      return false;
    }
    
    if (method !== 'S256') {
      console.warn('Unsupported PKCE method:', method);
      return false;
    }
    
    // Generate challenge from provided verifier
    const computedChallenge = generateCodeChallenge(codeVerifier);
    
    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(computedChallenge),
      Buffer.from(storedCodeChallenge)
    );
  } catch (error) {
    console.error('PKCE verification error:', error);
    return false;
  }
}

/**
 * Generate a cryptographically secure state parameter for OAuth
 * @param {Object} stateData - Data to include in state (user ID, provider, etc.)
 * @returns {string} Encrypted and base64-encoded state parameter
 */
export function generateOAuthState(stateData) {
  try {
    // Add timestamp and nonce for security
    const enhancedState = {
      ...stateData,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex')
    };
    
    // Convert to JSON and base64 encode (in production, encrypt this)
    return Buffer.from(JSON.stringify(enhancedState)).toString('base64url');
  } catch (error) {
    console.error('OAuth state generation error:', error);
    throw new Error('Failed to generate OAuth state');
  }
}

/**
 * Validate and decode OAuth state parameter
 * @param {string} state - Base64-encoded state parameter
 * @param {number} maxAge - Maximum age in milliseconds (default: 10 minutes)
 * @returns {{ success: boolean, data?: Object, error?: string }}
 */
export function validateOAuthState(state, maxAge = 10 * 60 * 1000) {
  try {
    if (!state || typeof state !== 'string') {
      return {
        success: false,
        error: 'Invalid state parameter'
      };
    }
    
    // Decode base64
    const decoded = Buffer.from(state, 'base64url').toString();
    const stateData = JSON.parse(decoded);
    
    // Validate timestamp
    if (!stateData.timestamp || typeof stateData.timestamp !== 'number') {
      return {
        success: false,
        error: 'Invalid state timestamp'
      };
    }
    
    const age = Date.now() - stateData.timestamp;
    if (age > maxAge) {
      return {
        success: false,
        error: 'State parameter expired'
      };
    }
    
    // Validate required fields
    if (!stateData.nonce || !stateData.userId || !stateData.provider) {
      return {
        success: false,
        error: 'Missing required state fields'
      };
    }
    
    return {
      success: true,
      data: stateData
    };
  } catch (error) {
    console.error('OAuth state validation error:', error);
    return {
      success: false,
      error: 'State validation failed'
    };
  }
}
