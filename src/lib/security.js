/**
 * Security monitoring and activity detection utilities
 * Handles device fingerprinting, location tracking, and suspicious activity detection
 * @author IdP System
 */

// TODO: MONITORING - Implement metrics collection and alerting for security events
import { UAParser } from 'ua-parser-js';
import { createSecureHash } from './auth.js';
import { prisma } from './database.js';

/**
 * Parse user agent string to extract device information
 * @param {string} userAgent - User agent string
 * @returns {{success: boolean, error: string|null, data: Object|null}}
 */
export function parseUserAgent(userAgent) {
  try {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();
    
    return {
      success: true,
      error: null,
      data: {
        browser: `${result.browser.name || 'Unknown'} ${result.browser.version || ''}`.trim(),
        os: `${result.os.name || 'Unknown'} ${result.os.version || ''}`.trim(),
        device: result.device.type || 'desktop',
        deviceModel: result.device.model || null,
        deviceVendor: result.device.vendor || null
      }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'User agent parsing failed',
      data: null
    };
  }
}

/**
 * Get location information from IP address
 * @param {string} ipAddress - IP address
 * @returns {{success: boolean, error: string|null, data: Object|null}}
 */
export async function getLocationFromIp(ipAddress) {
  try {
    // Skip local/private IPs
    // TODO: SECURITY - Add proper IP validation and sanitization
    // TODO: PRIVACY - Add user consent for geolocation tracking
    // TODO: PERFORMANCE - Cache geolocation results to avoid repeated API calls
    if (ipAddress === '127.0.0.1' || ipAddress === '::1' || ipAddress.startsWith('192.168.') || ipAddress.startsWith('10.')) {
      return {
        success: true,
        error: null,
        data: {
          country: 'Local',
          city: 'Local',
          region: 'Local',
          timezone: null,
          latitude: null,
          longitude: null
        }
      };
    }

    // Try to dynamically import geoip-lite
    let geoip;
    try {
      const geoipModule = await import('geoip-lite');
      geoip = geoipModule.default;
    } catch (importError) {
      // If geoip-lite is not available, return unknown location
      return {
        success: true,
        error: null,
        data: {
          country: 'Unknown',
          city: 'Unknown',
          region: 'Unknown',
          timezone: null,
          latitude: null,
          longitude: null
        }
      };
    }

    const geo = geoip.lookup(ipAddress);
    
    if (!geo) {
      return {
        success: true,
        error: null,
        data: {
          country: 'Unknown',
          city: 'Unknown',
          region: 'Unknown',
          timezone: null,
          latitude: null,
          longitude: null
        }
      };
    }

    return {
      success: true,
      error: null,
      data: {
        country: geo.country || 'Unknown',
        city: geo.city || 'Unknown',
        region: geo.region || 'Unknown',
        timezone: geo.timezone || null,
        latitude: geo.ll ? geo.ll[0] : null,
        longitude: geo.ll ? geo.ll[1] : null
      }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Location lookup failed',
      data: null
    };
  }
}

/**
 * Create device fingerprint
 * @param {string} userAgent - User agent string
 * @param {string} ipAddress - IP address
 * @param {Object} [additionalData] - Additional fingerprinting data
 * @returns {{success: boolean, error: string|null, data: string|null}}
 */
export function createDeviceFingerprint(userAgent, ipAddress, additionalData = {}) {
  try {
    const fingerprintData = {
      userAgent,
      ip: ipAddress,
      ...additionalData
    };
    
    const fingerprintString = JSON.stringify(fingerprintData);
    const fingerprint = createSecureHash(fingerprintString);
    
    return {
      success: true,
      error: null,
      data: fingerprint
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Device fingerprint creation failed',
      data: null
    };
  }
}

/**
 * Check if login activity is suspicious
 * @param {string} userId - User ID
 * @param {string} ipAddress - Current IP address
 * @param {string} userAgent - Current user agent
 * @returns {Promise<{success: boolean, error: string|null, data: Object}>}
 */
export async function checkSuspiciousActivity(userId, ipAddress, userAgent) {
  try {
    // Get user's recent login activity (last 30 days)
    const recentActivity = await prisma.loginActivity.findMany({
      where: {
        userId,
        timestamp: {
          gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
        }
      },
      orderBy: { timestamp: 'desc' },
      take: 50
    });

    const currentLocation = await getLocationFromIp(ipAddress);
    const currentDevice = parseUserAgent(userAgent);
    
    const suspiciousFlags = [];
    
    // Check for new country
    if (currentLocation.success && currentLocation.data.country !== 'Unknown' && currentLocation.data.country !== 'Local') {
      const recentCountries = [...new Set(recentActivity.map(a => a.country).filter(Boolean))];
      if (recentCountries.length > 0 && !recentCountries.includes(currentLocation.data.country)) {
        suspiciousFlags.push({
          type: 'new_country',
          message: `Login from new country: ${currentLocation.data.country}`,
          severity: 'high'
        });
      }
    }

    // Check for new device/browser
    if (currentDevice.success) {
      const recentUserAgents = recentActivity.map(a => a.userAgent).filter(Boolean);
      const deviceMatch = recentUserAgents.some(ua => {
        const parsed = parseUserAgent(ua);
        return parsed.success && 
               parsed.data.browser === currentDevice.data.browser &&
               parsed.data.os === currentDevice.data.os;
      });
      
      if (!deviceMatch && recentUserAgents.length > 0) {
        suspiciousFlags.push({
          type: 'new_device',
          message: `Login from new device: ${currentDevice.data.browser} on ${currentDevice.data.os}`,
          severity: 'medium'
        });
      }
    }

    // Check for rapid successive logins from different locations
    const last24Hours = recentActivity.filter(a => 
      new Date(a.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
    );
    
    if (last24Hours.length > 5) {
      const uniqueCountries = [...new Set(last24Hours.map(a => a.country).filter(Boolean))];
      if (uniqueCountries.length > 2) {
        suspiciousFlags.push({
          type: 'multiple_locations',
          message: `Multiple login locations in 24 hours: ${uniqueCountries.join(', ')}`,
          severity: 'high'
        });
      }
    }

    // Check for high frequency login attempts
    const lastHour = recentActivity.filter(a => 
      new Date(a.timestamp) > new Date(Date.now() - 60 * 60 * 1000)
    );
    
    if (lastHour.length > 10) {
      suspiciousFlags.push({
        type: 'high_frequency',
        message: `${lastHour.length} login attempts in the last hour`,
        severity: 'high'
      });
    }

    const riskLevel = suspiciousFlags.some(flag => flag.severity === 'high') ? 'high' :
                     suspiciousFlags.some(flag => flag.severity === 'medium') ? 'medium' : 'low';

    return {
      success: true,
      error: null,
      data: {
        isSuspicious: suspiciousFlags.length > 0,
        riskLevel,
        flags: suspiciousFlags,
        location: currentLocation.success ? currentLocation.data : null,
        device: currentDevice.success ? currentDevice.data : null
      }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Suspicious activity check failed',
      data: {
        isSuspicious: false,
        riskLevel: 'unknown',
        flags: [],
        location: null,
        device: null
      }
    };
  }
}

/**
 * Log security event
 * @param {string|Object} userIdOrEventData - User ID or complete event data object
 * @param {string} [event] - Event type (when first param is userId)
 * @param {Object} [details] - Event details (when first param is userId)
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function logSecurityEvent(userIdOrEventData, event, details = {}) {
  try {
    let eventData;
    
    // Support both calling formats:
    // logSecurityEvent({userId, event, ipAddress, ...}) - object format
    // logSecurityEvent(userId, event, {ipAddress, ...}) - parameter format
    if (typeof userIdOrEventData === 'object' && userIdOrEventData !== null) {
      // Object format
      eventData = userIdOrEventData;
    } else {
      // Parameter format
      eventData = {
        userId: userIdOrEventData,
        event: event,
        ipAddress: details.ipAddress || 'unknown',
        userAgent: details.userAgent || null,
        details: details
      };
    }

    const securityLog = await prisma.securityLog.create({
      data: {
        userId: eventData.userId || null,
        event: eventData.event,
        details: eventData.details || null,
        ipAddress: eventData.ipAddress || 'unknown',
        userAgent: eventData.userAgent || null,
        timestamp: new Date()
      }
    });

    return {
      success: true,
      error: null,
      data: securityLog
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Security event logging failed',
      data: null
    };
  }
}

/**
 * Check if device is trusted
 * @param {string} userId - User ID
 * @param {string} deviceFingerprint - Device fingerprint
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function checkTrustedDevice(userId, deviceFingerprint) {
  try {
    const trustedDevice = await prisma.trustedDevice.findFirst({
      where: {
        userId,
        deviceHash: deviceFingerprint,
        isActive: true
      }
    });

    return {
      success: true,
      error: null,
      data: trustedDevice
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Trusted device check failed',
      data: null
    };
  }
}

/**
 * Add device to trusted list
 * @param {Object} deviceData - Device data
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function addTrustedDevice(deviceData) {
  try {
    const trustedDevice = await prisma.trustedDevice.create({
      data: {
        userId: deviceData.userId,
        deviceHash: deviceData.fingerprint,
        deviceName: deviceData.name || null,
        firstIP: deviceData.ipAddress,
        lastIP: deviceData.ipAddress,
        metadata: {
          userAgent: deviceData.userAgent,
          ...deviceData.metadata
        },
        lastSeen: new Date(),
        isActive: true
      }
    });

    return {
      success: true,
      error: null,
      data: trustedDevice
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Trusted device addition failed',
      data: null
    };
  }
}

/**
 * Remove device from trusted list
 * @param {string} userId - User ID
 * @param {string} deviceId - Device ID
 * @returns {Promise<{success: boolean, error: string|null}>}
 */
export async function removeTrustedDevice(userId, deviceId) {
  try {
    await prisma.trustedDevice.updateMany({
      where: {
        userId,
        id: deviceId  // Use 'id' field instead of 'deviceId'
      },
      data: {
        isActive: false
      }
    });

    return {
      success: true,
      error: null
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Trusted device removal failed'
    };
  }
}
