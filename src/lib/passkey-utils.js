/**
 * Passkey Detection Utilities
 * Functions to detect passkey support and secure device fingerprinting
 * @author IdP System
 */

import { createHash } from 'crypto';

// Cache for device fingerprint to avoid recalculation
let cachedFingerprint = null;
let consentGiven = false;

/**
 * Check if the current device supports passkeys
 * @returns {Promise<boolean>}
 */
export async function supportsPasskeys() {
  try {
    // Check if WebAuthn is available
    if (!window.PublicKeyCredential) {
      return false;
    }

    // Check if conditional UI is supported (indicates better passkey support)
    if (typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
      const conditionalSupport = await PublicKeyCredential.isConditionalMediationAvailable();
      if (conditionalSupport) return true;
    }

    // Check if user verifying platform authenticator is available
    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }

    // Fallback - basic WebAuthn support
    return true;
  } catch (error) {
    console.error('Error checking passkey support:', error);
    return false;
  }
}

/**
 * Check if this device has been verified by the server as trusted
 * @param {string} userId - User ID to check device trust for
 * @returns {Promise<{success: boolean, error: string|null, data?: {trusted: boolean, deviceId?: string}}>}
 */
export async function isTrustedDevice(userId) {
  try {
    if (!userId) {
      return {
        success: false,
        error: 'User ID is required for device verification',
        data: { trusted: false }
      };
    }

    // Get device fingerprint with user consent
    const fingerprintResult = await getSecureDeviceFingerprint();
    if (!fingerprintResult.success) {
      return {
        success: false,
        error: fingerprintResult.error,
        data: { trusted: false }
      };
    }

    // Check with server if this device is trusted for this user
    try {
      const response = await fetch('/api/devices/check-trust', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId,
          deviceFingerprint: fingerprintResult.data.fingerprint
        }),
        credentials: 'include' // Include session cookies
      });

      if (!response.ok) {
        return {
          success: false,
          error: 'Failed to verify device trust with server',
          data: { trusted: false }
        };
      }

      const result = await response.json();
      return {
        success: true,
        error: null,
        data: {
          trusted: result.trusted || false,
          deviceId: result.deviceId,
          lastSeen: result.lastSeen
        }
      };

    } catch (networkError) {
      // Fallback to local basic checks only if server is unavailable
      console.warn('Server device verification unavailable, using fallback');
      const hasWebAuthnSupport = await supportsPasskeys();
      
      return {
        success: true,
        error: null,
        data: {
          trusted: hasWebAuthnSupport, // Basic fallback - devices with passkey support are more trusted
          fallback: true
        }
      };
    }

  } catch (error) {
    console.error('Device trust check error:', error);
    return {
      success: false,
      error: 'Device trust verification failed',
      data: { trusted: false }
    };
  }
}

/**
 * Request user consent for device fingerprinting
 * @returns {Promise<boolean>} Whether consent was given
 */
async function requestFingerprintingConsent() {
  if (consentGiven) {
    return true;
  }

  // In a real implementation, this would show a proper consent dialog
  // For now, we'll use a simple confirm dialog
  try {
    const consent = confirm(
      'This application would like to create a device identifier to enhance security and prevent fraud. ' +
      'This helps us detect unusual activity and protect your account. ' +
      'No personally identifiable information is collected. Do you consent?'
    );
    
    consentGiven = consent;
    return consent;
  } catch (error) {
    console.error('Error requesting consent:', error);
    return false;
  }
}

/**
 * Generate secure device fingerprint with privacy controls and cryptographic hashing
 * @returns {Promise<{success: boolean, error: string|null, data?: {fingerprint: string, factors: string[]}}>}
 */
export async function getSecureDeviceFingerprint() {
  try {
    // Check for user consent first
    const hasConsent = await requestFingerprintingConsent();
    if (!hasConsent) {
      return {
        success: false,
        error: 'User consent required for device fingerprinting',
        data: null
      };
    }

    // Return cached fingerprint if available
    if (cachedFingerprint) {
      return {
        success: true,
        error: null,
        data: { fingerprint: cachedFingerprint, cached: true }
      };
    }

    // Collect privacy-respecting device characteristics
    const factors = [];
    const factorNames = [];

    // Basic browser characteristics (not personally identifiable)
    if (navigator.userAgent) {
      // Hash the user agent to avoid exposing full string
      const hashedUA = await hashString(navigator.userAgent.substring(0, 50));
      factors.push(hashedUA);
      factorNames.push('browser_signature');
    }

    if (navigator.language) {
      factors.push(navigator.language);
      factorNames.push('language');
    }

    if (screen.width && screen.height) {
      factors.push(`${screen.width}x${screen.height}`);
      factorNames.push('screen_resolution');
    }

    if (typeof navigator.hardwareConcurrency === 'number') {
      factors.push(navigator.hardwareConcurrency.toString());
      factorNames.push('cpu_cores');
    }

    if (navigator.platform) {
      factors.push(navigator.platform);
      factorNames.push('platform');
    }

    // Timezone (rounded to hour to reduce precision)
    const timezone = Math.round(new Date().getTimezoneOffset() / 60);
    factors.push(timezone.toString());
    factorNames.push('timezone_hour');

    // WebAuthn support characteristics
    if (window.PublicKeyCredential) {
      factors.push('webauthn_supported');
      factorNames.push('webauthn_capability');
    }

    if (typeof PublicKeyCredential?.isConditionalMediationAvailable === 'function') {
      const conditionalSupport = await PublicKeyCredential.isConditionalMediationAvailable();
      factors.push(conditionalSupport ? 'conditional_ui' : 'no_conditional_ui');
      factorNames.push('conditional_ui_support');
    }

    // Create cryptographically secure fingerprint
    const combinedFactors = factors.join('|');
    const fingerprint = await hashString(combinedFactors);
    
    // Cache the result
    cachedFingerprint = fingerprint;

    return {
      success: true,
      error: null,
      data: {
        fingerprint: fingerprint,
        factors: factorNames, // Return factor names for transparency
        timestamp: new Date().toISOString()
      }
    };

  } catch (error) {
    console.error('Error generating secure device fingerprint:', error);
    return {
      success: false,
      error: 'Failed to generate device fingerprint',
      data: null
    };
  }
}

/**
 * Hash a string using Web Crypto API (browser) or crypto module (Node.js)
 * @param {string} input - String to hash
 * @returns {Promise<string>} Hexadecimal hash
 */
async function hashString(input) {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    // Browser environment - use Web Crypto API
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
  } else {
    // Node.js environment - use crypto module
    const hash = createHash('sha256');
    hash.update(input);
    return hash.digest('hex').substring(0, 32);
  }
}

/**
 * Legacy device fingerprint function (deprecated)
 * @deprecated Use getSecureDeviceFingerprint() instead
 * @returns {string}
 */
export function getDeviceFingerprint() {
  console.warn('getDeviceFingerprint() is deprecated. Use getSecureDeviceFingerprint() instead.');
  
  try {
    // Provide basic fallback that doesn't use problematic methods
    const basicFactors = [
      navigator.language || 'unknown',
      screen.width + 'x' + screen.height || 'unknown',
      navigator.platform || 'unknown'
    ];

    // Simple non-cryptographic hash for backward compatibility
    let hash = 0;
    const str = basicFactors.join('|');
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    
    return Math.abs(hash).toString(16).substring(0, 16);
  } catch (error) {
    console.error('Error generating legacy device fingerprint:', error);
    return 'fallback_device_id';
  }
}

/**
 * Store device information for trust scoring
 * @param {boolean} isLoginSuccess - Whether login was successful
 */
export function updateDeviceTrust(isLoginSuccess = true) {
  try {
    const fingerprint = getDeviceFingerprint();
    const timestamp = Date.now();
    
    // Update device fingerprint
    localStorage.setItem('deviceFingerprint', fingerprint);
    
    if (isLoginSuccess) {
      localStorage.setItem('lastLogin', timestamp.toString());
      
      // Increment successful login count
      const loginCount = parseInt(localStorage.getItem('loginCount') || '0') + 1;
      localStorage.setItem('loginCount', loginCount.toString());
    }
  } catch (error) {
    console.error('Error updating device trust:', error);
  }
}

/**
 * Check if user should be prompted for passkey setup
 * @returns {Promise<boolean>}
 */
export async function shouldPromptPasskeySetup() {
  try {
    // Don't prompt if already dismissed recently
    const dismissedAt = localStorage.getItem('passkeyPromptDismissed');
    if (dismissedAt) {
      const dismissedTime = parseInt(dismissedAt);
      const daysSinceDismissed = (Date.now() - dismissedTime) / (1000 * 60 * 60 * 24);
      if (daysSinceDismissed < 7) { // Don't prompt again for 7 days
        return false;
      }
    }

    // Check if device supports passkeys
    const hasPasskeySupport = await supportsPasskeys();
    if (!hasPasskeySupport) {
      return false;
    }

    // Check if this is a trusted device
    const isTrusted = isTrustedDevice();
    if (!isTrusted) {
      return false;
    }

    // Check login count (only prompt for returning users)
    const loginCount = parseInt(localStorage.getItem('loginCount') || '0');
    if (loginCount < 2) {
      return false;
    }

    return true;
  } catch (error) {
    console.error('Error checking passkey setup prompt:', error);
    return false;
  }
}

/**
 * Mark passkey prompt as dismissed
 */
export function dismissPasskeyPrompt() {
  try {
    localStorage.setItem('passkeyPromptDismissed', Date.now().toString());
  } catch (error) {
    console.error('Error dismissing passkey prompt:', error);
  }
}
