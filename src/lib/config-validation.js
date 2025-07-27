/**
 * Configuration Validation Utilities
 * Validates required environment variables and configuration
 * @author IdP System
 */

/**
 * Required environment variables for email service
 */
const REQUIRED_EMAIL_ENV_VARS = [
  'SMTP_HOST',
  'SMTP_PORT', 
  'SMTP_USER',
  'SMTP_PASS',
  'EMAIL_FROM',
  'APP_NAME',
  'APP_URL'
];

/**
 * Required environment variables for authentication
 */
const REQUIRED_AUTH_ENV_VARS = [
  'JWT_SECRET',
  'APP_URL',
  'DATABASE_URL'
];

/**
 * Required environment variables for OAuth
 */
const REQUIRED_OAUTH_ENV_VARS = [
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GITHUB_CLIENT_ID', 
  'GITHUB_CLIENT_SECRET'
];

/**
 * Validate required environment variables
 * @param {string[]} requiredVars - Array of required variable names
 * @param {string} context - Context for error messages (e.g., 'email', 'auth')
 * @returns {{ success: boolean, error: string|null, missing: string[] }}
 */
export function validateEnvironmentVariables(requiredVars, context = 'application') {
  try {
    const missing = [];
    const empty = [];

    for (const varName of requiredVars) {
      const value = process.env[varName];
      
      if (!value) {
        missing.push(varName);
      } else if (typeof value === 'string' && value.trim() === '') {
        empty.push(varName);
      }
    }

    const allMissing = [...missing, ...empty];
    
    if (allMissing.length > 0) {
      const error = `Missing or empty environment variables for ${context}: ${allMissing.join(', ')}`;
      console.error('Configuration validation failed:', error);
      
      return {
        success: false,
        error,
        missing: allMissing
      };
    }

    return {
      success: true,
      error: null,
      missing: []
    };
  } catch (error) {
    console.error('Environment validation error:', error);
    return {
      success: false,
      error: 'Environment validation failed',
      missing: requiredVars
    };
  }
}

/**
 * Validate email configuration environment variables
 * @returns {{ success: boolean, error: string|null, missing: string[] }}
 */
export function validateEmailConfig() {
  const validation = validateEnvironmentVariables(REQUIRED_EMAIL_ENV_VARS, 'email service');
  
  if (!validation.success) {
    return validation;
  }

  // Additional email-specific validations
  const smtpPort = parseInt(process.env.SMTP_PORT, 10);
  if (isNaN(smtpPort) || smtpPort < 1 || smtpPort > 65535) {
    return {
      success: false,
      error: 'SMTP_PORT must be a valid port number (1-65535)',
      missing: ['SMTP_PORT']
    };
  }

  // Validate APP_URL format
  const appUrl = process.env.APP_URL;
  try {
    new URL(appUrl);
  } catch {
    return {
      success: false,
      error: 'APP_URL must be a valid URL',
      missing: ['APP_URL']
    };
  }

  // Validate EMAIL_FROM format
  const emailFrom = process.env.EMAIL_FROM;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(emailFrom)) {
    return {
      success: false,
      error: 'EMAIL_FROM must be a valid email address',
      missing: ['EMAIL_FROM']
    };
  }

  return {
    success: true,
    error: null,
    missing: []
  };
}

/**
 * Validate authentication configuration environment variables
 * @returns {{ success: boolean, error: string|null, missing: string[] }}
 */
export function validateAuthConfig() {
  const validation = validateEnvironmentVariables(REQUIRED_AUTH_ENV_VARS, 'authentication');
  
  if (!validation.success) {
    return validation;
  }

  // Validate JWT_SECRET strength
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret.length < 32) {
    return {
      success: false,
      error: 'JWT_SECRET must be at least 32 characters long for security',
      missing: ['JWT_SECRET']
    };
  }

  return {
    success: true,
    error: null,
    missing: []
  };
}

/**
 * Validate OAuth configuration environment variables
 * @returns {{ success: boolean, error: string|null, missing: string[] }}
 */
export function validateOAuthConfig() {
  // OAuth is optional, so we only validate if any OAuth vars are set
  const hasOAuthVars = REQUIRED_OAUTH_ENV_VARS.some(varName => process.env[varName]);
  
  if (!hasOAuthVars) {
    return {
      success: true,
      error: null,
      missing: []
    };
  }

  return validateEnvironmentVariables(REQUIRED_OAUTH_ENV_VARS, 'OAuth');
}

/**
 * Validate all application configuration
 * @returns {{ success: boolean, errors: string[], allValid: boolean }}
 */
export function validateAllConfig() {
  const results = {
    email: validateEmailConfig(),
    auth: validateAuthConfig(),
    oauth: validateOAuthConfig()
  };

  const errors = [];
  let allValid = true;

  for (const [service, result] of Object.entries(results)) {
    if (!result.success) {
      errors.push(`${service}: ${result.error}`);
      allValid = false;
    }
  }

  return {
    success: allValid,
    errors,
    allValid,
    details: results
  };
}

/**
 * Get safe configuration values (without secrets)
 * @returns {Object} Safe configuration object
 */
export function getSafeConfig() {
  return {
    appName: process.env.APP_NAME || 'Identity Provider',
    appUrl: process.env.APP_URL || 'http://localhost:3000',
    nodeEnv: process.env.NODE_ENV || 'development',
    smtpHost: process.env.SMTP_HOST,
    smtpPort: process.env.SMTP_PORT,
    emailFrom: process.env.EMAIL_FROM,
    hasGoogleOAuth: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
    hasGitHubOAuth: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET)
  };
}

/**
 * Check if running in production
 * @returns {boolean} True if in production environment
 */
export function isProduction() {
  return process.env.NODE_ENV === 'production';
}

/**
 * Check if running in development
 * @returns {boolean} True if in development environment
 */
export function isDevelopment() {
  return process.env.NODE_ENV === 'development';
}
