/**
 * Passkey Detection Utilities
 * Functions to detect passkey support and trusted devices
 * @author IdP System
 */

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
 * Check if this appears to be a trusted device based on various factors
 * @returns {boolean}
 */
export function isTrustedDevice() {
  try {
    // Check if device has been used before (localStorage indicates returning user)
    const hasLocalData = localStorage.getItem('deviceFingerprint') || 
                        localStorage.getItem('lastLogin') ||
                        localStorage.getItem('userPreferences');

    // Check device characteristics that suggest it's a personal device
    const hasGoodUserAgent = navigator.userAgent && 
                           !navigator.userAgent.includes('bot') && 
                           !navigator.userAgent.includes('crawler');

    // Check for persistent features (touch support, screen info)
    const hasPersonalFeatures = 'ontouchstart' in window || 
                               navigator.maxTouchPoints > 0 ||
                               (screen.width > 0 && screen.height > 0);

    // Check if device supports modern security features
    const hasSecurityFeatures = 'serviceWorker' in navigator ||
                               window.crypto && window.crypto.subtle;

    return hasLocalData && hasGoodUserAgent && hasPersonalFeatures && hasSecurityFeatures;
  } catch (error) {
    console.error('Error checking trusted device:', error);
    return false;
  }
}

/**
 * Get device fingerprint for tracking
 * @returns {string}
 */
export function getDeviceFingerprint() {
  try {
    const factors = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      navigator.platform,
      navigator.cookieEnabled,
      navigator.onLine
    ];

    // Create a simple hash
    const fingerprint = factors.join('|');
    return btoa(fingerprint).substring(0, 16);
  } catch (error) {
    console.error('Error generating device fingerprint:', error);
    return 'unknown';
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
