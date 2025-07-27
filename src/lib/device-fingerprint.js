/**
 * Client-side Device Fingerprinting
 * Creates unique device identifiers for trusted device functionality
 * @author IdP System
 */

/**
 * Generate a device fingerprint based on browser capabilities and characteristics
 * @returns {Promise<{success: boolean, error: string|null, data: string|null}>}
 */
export async function generateDeviceFingerprint() {
  try {
    const fingerprint = {
      // Screen characteristics
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth
      },
      
      // Timezone
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset(),
      
      // Language preferences
      language: navigator.language,
      languages: navigator.languages,
      
      // Platform info
      platform: navigator.platform,
      userAgent: navigator.userAgent,
      
      // Hardware info (if available)
      hardwareConcurrency: navigator.hardwareConcurrency,
      deviceMemory: navigator.deviceMemory || null,
      
      // Canvas fingerprint (basic)
      canvas: await getCanvasFingerprint(),
      
      // WebGL info
      webgl: getWebGLFingerprint(),
      
      // Audio context fingerprint
      audio: await getAudioFingerprint()
    };

    // Create a hash of all the collected data
    const fingerprintString = JSON.stringify(fingerprint);
    const fingerprintHash = await hashString(fingerprintString);
    
    return {
      success: true,
      error: null,
      data: fingerprintHash
    };
  } catch (error) {
    return {
      success: false,
      error: error?.message || 'Device fingerprinting failed',
      data: null
    };
  }
}

/**
 * Generate canvas fingerprint
 * @returns {Promise<string>}
 */
async function getCanvasFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    // Draw some text and shapes to create a unique fingerprint
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprint canvas', 2, 2);
    ctx.fillStyle = 'rgba(255, 0, 0, 0.5)';
    ctx.fillRect(0, 0, 100, 50);
    
    return canvas.toDataURL();
  } catch (error) {
    return 'canvas-not-supported';
  }
}

/**
 * Get WebGL fingerprint
 * @returns {Object}
 */
function getWebGLFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    
    if (!gl) {
      return { supported: false };
    }
    
    return {
      supported: true,
      vendor: gl.getParameter(gl.VENDOR),
      renderer: gl.getParameter(gl.RENDERER),
      version: gl.getParameter(gl.VERSION),
      shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION)
    };
  } catch (error) {
    return { supported: false, error: error.message };
  }
}

/**
 * Generate audio context fingerprint
 * @returns {Promise<string>}
 */
async function getAudioFingerprint() {
  try {
    // Check if AudioContext is available
    if (!window.AudioContext && !window.webkitAudioContext) {
      return 'audio-not-supported';
    }
    
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    const context = new AudioContext();
    
    // Create oscillator
    const oscillator = context.createOscillator();
    const analyser = context.createAnalyser();
    const gain = context.createGain();
    const scriptProcessor = context.createScriptProcessor(4096, 1, 1);
    
    oscillator.type = 'triangle';
    oscillator.frequency.setValueAtTime(10000, context.currentTime);
    
    gain.gain.setValueAtTime(0, context.currentTime);
    
    oscillator.connect(analyser);
    analyser.connect(scriptProcessor);
    scriptProcessor.connect(gain);
    gain.connect(context.destination);
    
    oscillator.start(0);
    
    return new Promise((resolve) => {
      scriptProcessor.onaudioprocess = function(bins) {
        const audioData = bins.inputBuffer.getChannelData(0);
        let hash = 0;
        
        for (let i = 0; i < audioData.length; i++) {
          hash += Math.abs(audioData[i]);
        }
        
        oscillator.stop();
        context.close();
        resolve(hash.toString());
      };
      
      // Fallback timeout
      setTimeout(() => {
        oscillator.stop();
        context.close();
        resolve('audio-timeout');
      }, 1000);
    });
  } catch (error) {
    return 'audio-error';
  }
}

/**
 * Hash a string using SubtleCrypto API
 * @param {string} str - String to hash
 * @returns {Promise<string>}
 */
async function hashString(str) {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hash = await crypto.subtle.digest('SHA-256', data);
    
    // Convert to hex string
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  } catch (error) {
    // Fallback to simple hash if SubtleCrypto is not available
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }
}

/**
 * Get a simplified device name for display purposes
 * @returns {string}
 */
export function getDeviceDisplayName() {
  const ua = navigator.userAgent;
  let deviceName = 'Unknown Device';
  
  // Detect mobile devices
  if (/iPhone/i.test(ua)) {
    deviceName = 'iPhone';
  } else if (/iPad/i.test(ua)) {
    deviceName = 'iPad';
  } else if (/Android/i.test(ua)) {
    deviceName = 'Android Device';
  } else if (/Mac/i.test(ua)) {
    deviceName = 'Mac';
  } else if (/Windows/i.test(ua)) {
    deviceName = 'Windows PC';
  } else if (/Linux/i.test(ua)) {
    deviceName = 'Linux PC';
  }
  
  // Add browser info
  let browser = 'Unknown Browser';
  if (/Chrome/i.test(ua) && !/Edge/i.test(ua)) {
    browser = 'Chrome';
  } else if (/Firefox/i.test(ua)) {
    browser = 'Firefox';
  } else if (/Safari/i.test(ua) && !/Chrome/i.test(ua)) {
    browser = 'Safari';
  } else if (/Edge/i.test(ua)) {
    browser = 'Edge';
  }
  
  return `${deviceName} (${browser})`;
}
