/**
 * Multi-Factor Authentication (MFA) utilities
 * Handles TOTP generation, QR codes, and backup codes
 * @author IdP System
 */

import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { generateRandomString } from './auth.js';

/**
 * Generate TOTP secret for a user
 * @param {string} userEmail - User's email
 * @param {string} [serviceName] - Service name for TOTP app
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function generateTotpSecret(userEmail, serviceName) {
  try {
    const service = serviceName || process.env.MFA_SERVICE_NAME || 'NS101 Accounts';
    const issuer = process.env.MFA_ISSUER || 'NS101 Development';
    
    const secret = speakeasy.generateSecret({
      name: `${service} (${userEmail})`,
      issuer: issuer,
      length: 32
    });

    return {
      success: true,
      error: null,
      data: {
        secret: secret.base32,
        otpauthUrl: secret.otpauth_url,
        manualEntryKey: secret.base32
      }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'TOTP secret generation failed',
      data: null
    };
  }
}

/**
 * Generate QR code for TOTP setup
 * @param {string} otpauthUrl - OTPAUTH URL from TOTP secret
 * @returns {Promise<{success: boolean, error: string|null, data: string|null}>}
 */
export async function generateQrCode(otpauthUrl) {
  try {
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
    
    return {
      success: true,
      error: null,
      data: qrCodeDataUrl
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'QR code generation failed',
      data: null
    };
  }
}

/**
 * Verify TOTP token
 * @param {string} token - 6-digit TOTP token
 * @param {string} secret - User's TOTP secret
 * @param {number} [window=1] - Time window for verification
 * @returns {Promise<{success: boolean, error: string|null, data: boolean}>}
 */
export async function verifyTotpToken(token, secret, window = 1) {
  try {
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: window
    });

    return {
      success: true,
      error: null,
      data: verified
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'TOTP verification failed',
      data: false
    };
  }
}

/**
 * Generate backup codes for MFA
 * @param {number} [count=8] - Number of backup codes to generate
 * @returns {Promise<{success: boolean, error: string|null, data: string[]}>}
 */
export async function generateBackupCodes(count = 8) {
  try {
    const codes = [];
    
    for (let i = 0; i < count; i++) {
      // Generate 8-character alphanumeric codes
      const code = generateRandomString(8).toUpperCase();
      codes.push(code);
    }

    return {
      success: true,
      error: null,
      data: codes
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Backup code generation failed',
      data: []
    };
  }
}

/**
 * Verify backup code
 * @param {string} inputCode - Code entered by user
 * @param {string[]} backupCodes - Array of valid backup codes
 * @returns {{success: boolean, error: string|null, data: {isValid: boolean, remainingCodes: string[]}}}
 */
export function verifyBackupCode(inputCode, backupCodes) {
  try {
    const normalizedInput = inputCode.toUpperCase().trim();
    const codeIndex = backupCodes.findIndex(code => code === normalizedInput);
    
    if (codeIndex === -1) {
      return {
        success: true,
        error: null,
        data: {
          isValid: false,
          remainingCodes: backupCodes
        }
      };
    }

    // Remove used code from the array
    const remainingCodes = backupCodes.filter((_, index) => index !== codeIndex);
    
    return {
      success: true,
      error: null,
      data: {
        isValid: true,
        remainingCodes: remainingCodes
      }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Backup code verification failed',
      data: {
        isValid: false,
        remainingCodes: backupCodes
      }
    };
  }
}

/**
 * Generate current TOTP token (for testing/admin purposes)
 * @param {string} secret - TOTP secret
 * @returns {Promise<{success: boolean, error: string|null, data: string|null}>}
 */
export async function getCurrentTotpToken(secret) {
  try {
    const token = speakeasy.totp({
      secret: secret,
      encoding: 'base32'
    });

    return {
      success: true,
      error: null,
      data: token
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'TOTP token generation failed',
      data: null
    };
  }
}

/**
 * Validate MFA setup data
 * @param {Object} mfaData - MFA setup data
 * @param {string} mfaData.secret - TOTP secret
 * @param {string} mfaData.token - Verification token
 * @returns {Promise<{success: boolean, error: string|null, data: boolean}>}
 */
export async function validateMfaSetup(mfaData) {
  try {
    const { secret, token } = mfaData;
    
    if (!secret || !token) {
      return {
        success: false,
        error: 'Secret and token are required',
        data: false
      };
    }

    const verificationResult = await verifyTotpToken(token, secret);
    
    if (!verificationResult.success) {
      return verificationResult;
    }

    return {
      success: true,
      error: null,
      data: verificationResult.data
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'MFA setup validation failed',
      data: false
    };
  }
}
