/**
 * Standardized error codes and messages for API responses
 * Provides consistent error handling across the application
 * @author IdP System
 */

export const ERROR_CODES = {
  // Authentication errors
  AUTH_INVALID_CREDENTIALS: 'AUTH_001',
  AUTH_USER_NOT_FOUND: 'AUTH_002',
  AUTH_PASSWORD_INCORRECT: 'AUTH_003',
  AUTH_MFA_REQUIRED: 'AUTH_004',
  AUTH_MFA_INVALID: 'AUTH_005',
  AUTH_ACCOUNT_DISABLED: 'AUTH_006',
  AUTH_EMAIL_NOT_VERIFIED: 'AUTH_007',
  AUTH_SESSION_EXPIRED: 'AUTH_008',
  AUTH_TOKEN_INVALID: 'AUTH_009',
  AUTH_TOKEN_EXPIRED: 'AUTH_010',

  // Input validation errors
  VALIDATION_INVALID_EMAIL: 'VAL_001',
  VALIDATION_INVALID_PASSWORD: 'VAL_002',
  VALIDATION_MISSING_FIELDS: 'VAL_003',
  VALIDATION_INVALID_TOTP: 'VAL_004',
  VALIDATION_INVALID_BACKUP_CODE: 'VAL_005',

  // Rate limiting errors
  RATE_LIMIT_EXCEEDED: 'RATE_001',
  RATE_LIMIT_IP_BLOCKED: 'RATE_002',

  // System errors
  SYSTEM_ERROR: 'SYS_001',
  SYSTEM_DATABASE_ERROR: 'SYS_002',
  SYSTEM_EMAIL_ERROR: 'SYS_003',
  SYSTEM_CONFIG_ERROR: 'SYS_004'
};

export const ERROR_MESSAGES = {
  [ERROR_CODES.AUTH_INVALID_CREDENTIALS]: 'Invalid email or password',
  [ERROR_CODES.AUTH_USER_NOT_FOUND]: 'Invalid email or password',
  [ERROR_CODES.AUTH_PASSWORD_INCORRECT]: 'Invalid email or password',
  [ERROR_CODES.AUTH_MFA_REQUIRED]: 'Two-factor authentication required',
  [ERROR_CODES.AUTH_MFA_INVALID]: 'Invalid verification code',
  [ERROR_CODES.AUTH_ACCOUNT_DISABLED]: 'Account has been disabled',
  [ERROR_CODES.AUTH_EMAIL_NOT_VERIFIED]: 'Email address not verified',
  [ERROR_CODES.AUTH_SESSION_EXPIRED]: 'Session has expired',
  [ERROR_CODES.AUTH_TOKEN_INVALID]: 'Invalid authentication token',
  [ERROR_CODES.AUTH_TOKEN_EXPIRED]: 'Authentication token has expired',

  [ERROR_CODES.VALIDATION_INVALID_EMAIL]: 'Invalid email format',
  [ERROR_CODES.VALIDATION_INVALID_PASSWORD]: 'Invalid password format',
  [ERROR_CODES.VALIDATION_MISSING_FIELDS]: 'Required fields are missing',
  [ERROR_CODES.VALIDATION_INVALID_TOTP]: 'Invalid TOTP token format',
  [ERROR_CODES.VALIDATION_INVALID_BACKUP_CODE]: 'Invalid backup code format',

  [ERROR_CODES.RATE_LIMIT_EXCEEDED]: 'Too many requests, please try again later',
  [ERROR_CODES.RATE_LIMIT_IP_BLOCKED]: 'Your IP address has been temporarily blocked',

  [ERROR_CODES.SYSTEM_ERROR]: 'An unexpected error occurred',
  [ERROR_CODES.SYSTEM_DATABASE_ERROR]: 'Database error occurred',
  [ERROR_CODES.SYSTEM_EMAIL_ERROR]: 'Email service error',
  [ERROR_CODES.SYSTEM_CONFIG_ERROR]: 'Configuration error'
};

/**
 * Creates a standardized error response
 * @param {string} errorCode - Error code from ERROR_CODES
 * @param {string} [customMessage] - Custom error message (optional)
 * @param {Object} [metadata] - Additional error metadata
 * @returns {Object} Structured error response
 */
export function createErrorResponse(errorCode, customMessage = null, metadata = {}) {
  return {
    success: false,
    error: {
      code: errorCode,
      message: customMessage || ERROR_MESSAGES[errorCode] || 'Unknown error',
      timestamp: new Date().toISOString(),
      ...metadata
    }
  };
}

/**
 * Creates a standardized success response
 * @param {*} data - Response data
 * @param {Object} [metadata] - Additional metadata
 * @returns {Object} Structured success response
 */
export function createSuccessResponse(data, metadata = {}) {
  return {
    success: true,
    data,
    ...metadata
  };
}
