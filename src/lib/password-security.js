/**
 * Advanced Password Security Module
 * Comprehensive password validation with security-focused checks
 * @author IdP System
 */

import crypto from 'crypto';

/**
 * Common weak passwords list (top 500 most common passwords)
 * In production, this should be loaded from a secure external file
 * TODO: CONFIGURATION - Load from external secure configuration
 */
const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', 'guest', 'qwerty', '12345678', '111111',
  'password123', '123123', '1234567890', '1234567', 'password1', '12345',
  'hello', '1234', 'welcome', 'admin', 'administrator', 'root', 'toor',
  'pass', 'test', 'temp', 'temporary', '000000', '888888', '666666',
  'dragon', 'monkey', 'letmein', 'login', 'princess', 'qwertyuiop',
  'solo', 'passw0rd', 'starwars', 'firewall', 'master', '1q2w3e4r',
  'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter',
  'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine',
  'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger',
  'daniel', 'starwars', 'klaster', '112233', 'george', 'computer',
  'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111',
  '131313', 'freedom', '777777', 'pass123', 'maggie', '159753', 'aaaaaa',
  'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love',
  'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees',
  'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'minecraft',
  'samsung', 'qwerty123', 'iphone', 'jordan23', 'monkey', 'twitter'
]);

/**
 * Keyboard patterns that indicate weak passwords
 */
const KEYBOARD_PATTERNS = [
  /qwerty/i, /asdfgh/i, /zxcvbn/i, /123456/i, /654321/i,
  /qwertyuiop/i, /asdfghjkl/i, /zxcvbnm/i, /poiuytrewq/i,
  /mnbvcxz/i, /lkjhgfdsa/i, /098765/i, /567890/i,
  /abcdef/i, /fedcba/i, /987654/i, /456789/i
];

/**
 * Calculate password entropy score
 * @param {string} password - Password to analyze
 * @returns {number} Entropy score (bits)
 */
export function calculatePasswordEntropy(password) {
  if (!password || typeof password !== 'string') {
    return 0;
  }

  // Character set size calculation
  let charsetSize = 0;
  
  if (/[a-z]/.test(password)) charsetSize += 26; // lowercase
  if (/[A-Z]/.test(password)) charsetSize += 26; // uppercase  
  if (/[0-9]/.test(password)) charsetSize += 10; // numbers
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) charsetSize += 32; // special chars
  if (/[\s]/.test(password)) charsetSize += 1; // spaces
  
  // Additional character types
  if (/[àáâãäåæçèéêëìíîïñòóôõöùúûüý]/.test(password)) charsetSize += 50; // accented chars
  
  // Calculate entropy: H = L * log2(N)
  // where L = length, N = character set size
  const entropy = password.length * Math.log2(charsetSize);
  
  return Math.round(entropy * 100) / 100; // Round to 2 decimal places
}

/**
 * Check if password contains keyboard patterns
 * @param {string} password - Password to check
 * @returns {Array<string>} Array of detected patterns
 */
export function detectKeyboardPatterns(password) {
  const detectedPatterns = [];
  
  for (const pattern of KEYBOARD_PATTERNS) {
    if (pattern.test(password)) {
      detectedPatterns.push(`Contains keyboard pattern: ${pattern.source}`);
    }
  }
  
  // Check for repeated characters (3+ in a row)
  if (/(.)\1{2,}/.test(password)) {
    detectedPatterns.push('Contains repeated characters');
  }
  
  // Check for simple sequences
  if (/012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)) {
    detectedPatterns.push('Contains sequential characters');
  }
  
  return detectedPatterns;
}

/**
 * Check if password is in common password list
 * @param {string} password - Password to check
 * @returns {boolean} True if password is common/weak
 */
export function isCommonPassword(password) {
  if (!password || typeof password !== 'string') {
    return true;
  }
  
  const normalized = password.toLowerCase();
  
  // Direct match
  if (COMMON_PASSWORDS.has(normalized)) {
    return true;
  }
  
  // Check variations with simple modifications
  const variations = [
    normalized.replace(/[0-9]/g, ''), // Remove numbers
    normalized.replace(/[!@#$%^&*(),.?":{}|<>]/g, ''), // Remove special chars
    normalized.slice(0, -1), // Remove last character
    normalized.slice(1), // Remove first character
  ];
  
  for (const variation of variations) {
    if (variation.length >= 4 && COMMON_PASSWORDS.has(variation)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Comprehensive password strength analysis
 * @param {string} password - Password to analyze
 * @returns {{
 *   score: number,
 *   level: string,
 *   entropy: number,
 *   feedback: Array<string>,
 *   isSecure: boolean
 * }}
 */
export function analyzePasswordStrength(password) {
  if (!password || typeof password !== 'string') {
    return {
      score: 0,
      level: 'invalid',
      entropy: 0,
      feedback: ['Password is required'],
      isSecure: false
    };
  }

  const feedback = [];
  let score = 0;
  
  // Length scoring (0-30 points)
  if (password.length >= 12) {
    score += 30;
  } else if (password.length >= 8) {
    score += 20;
  } else if (password.length >= 6) {
    score += 10;
    feedback.push('Password should be at least 8 characters long');
  } else {
    feedback.push('Password is too short (minimum 6 characters)');
  }
  
  // Character variety scoring (0-40 points)
  let varietyScore = 0;
  if (/[a-z]/.test(password)) varietyScore += 5;
  if (/[A-Z]/.test(password)) varietyScore += 5;
  if (/[0-9]/.test(password)) varietyScore += 5;
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) varietyScore += 10;
  if (/[\s]/.test(password)) varietyScore += 5; // Spaces can strengthen passwords
  
  // Bonus for character diversity
  const uniqueChars = new Set(password.toLowerCase()).size;
  if (uniqueChars >= password.length * 0.7) varietyScore += 10;
  
  score += Math.min(varietyScore, 40);
  
  // Entropy scoring (0-20 points)
  const entropy = calculatePasswordEntropy(password);
  if (entropy >= 60) {
    score += 20;
  } else if (entropy >= 40) {
    score += 15;
  } else if (entropy >= 25) {
    score += 10;
  } else {
    feedback.push('Password complexity is too low');
  }
  
  // Security checks (deductions)
  if (isCommonPassword(password)) {
    score -= 30;
    feedback.push('Password is too common and easily guessable');
  }
  
  const patterns = detectKeyboardPatterns(password);
  if (patterns.length > 0) {
    score -= 15 * patterns.length;
    feedback.push(...patterns);
  }
  
  // Prevent negative scores
  score = Math.max(0, score);
  
  // Determine strength level
  let level;
  let isSecure = false;
  
  if (score >= 80) {
    level = 'very-strong';
    isSecure = true;
  } else if (score >= 60) {
    level = 'strong';
    isSecure = true;
  } else if (score >= 40) {
    level = 'moderate';
    feedback.push('Consider making your password stronger');
  } else if (score >= 20) {
    level = 'weak';
    feedback.push('Password is weak and not recommended');
  } else {
    level = 'very-weak';
    feedback.push('Password is very weak and unsafe');
  }
  
  // Add positive feedback for strong passwords
  if (isSecure && feedback.length === 0) {
    feedback.push('Excellent password strength!');
  }
  
  return {
    score,
    level,
    entropy,
    feedback,
    isSecure
  };
}

/**
 * Enhanced password validation with security focus
 * @param {string} password - Password to validate
 * @param {Object} options - Validation options
 * @param {number} options.minEntropy - Minimum entropy required (default: 30)
 * @param {boolean} options.blockCommon - Block common passwords (default: true)
 * @param {boolean} options.blockPatterns - Block keyboard patterns (default: true)
 * @returns {{
 *   isValid: boolean,
 *   errors: Array<string>,
 *   warnings: Array<string>,
 *   strength: Object
 * }}
 */
export function validatePasswordSecurity(password, options = {}) {
  const {
    minEntropy = 30,
    blockCommon = true,
    blockPatterns = true
  } = options;

  const errors = [];
  const warnings = [];
  
  // Basic validation
  if (!password || typeof password !== 'string') {
    errors.push('Password is required');
    return { isValid: false, errors, warnings, strength: null };
  }
  
  if (password.length < 8) {
    errors.push('Password must be at least 8 characters long');
  }
  
  if (password.length > 128) {
    errors.push('Password must be less than 128 characters long');
  }
  
  // Character requirements
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  // Security analysis
  const strength = analyzePasswordStrength(password);
  
  // Entropy check
  if (strength.entropy < minEntropy) {
    errors.push(`Password complexity is too low (entropy: ${strength.entropy}, required: ${minEntropy})`);
  }
  
  // Common password check
  if (blockCommon && isCommonPassword(password)) {
    errors.push('Password is too common and easily guessable. Please choose a more unique password.');
  }
  
  // Pattern detection
  if (blockPatterns) {
    const patterns = detectKeyboardPatterns(password);
    if (patterns.length > 0) {
      errors.push('Password contains predictable patterns. Please avoid keyboard sequences and repeated characters.');
    }
  }
  
  // Warnings for moderate security
  if (strength.entropy < 40 && strength.entropy >= minEntropy) {
    warnings.push('Consider using a longer password with more character variety');
  }
  
  if (strength.score < 60 && errors.length === 0) {
    warnings.push('Password meets minimum requirements but could be stronger');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
    warnings,
    strength
  };
}

/**
 * Generate secure password hash for comparison
 * Used for detecting password reuse
 * @param {string} password - Password to hash
 * @param {string} userId - User ID for salt
 * @returns {string} Secure hash for storage/comparison
 */
export function generatePasswordHash(password, userId) {
  if (!password || !userId) {
    throw new Error('Password and userId are required for hash generation');
  }
  
  // Create deterministic hash for password history comparison
  const salt = crypto.createHash('sha256').update(`${userId}:password_history`).digest('hex');
  return crypto.createHash('sha256').update(`${password}:${salt}`).digest('hex');
}

/**
 * Check if password has been used before
 * @param {string} password - New password to check
 * @param {string} userId - User ID
 * @param {Array<string>} passwordHistory - Array of previous password hashes
 * @returns {boolean} True if password was used before
 */
export function isPasswordReused(password, userId, passwordHistory = []) {
  if (!password || !userId || !Array.isArray(passwordHistory)) {
    return false;
  }
  
  const newPasswordHash = generatePasswordHash(password, userId);
  return passwordHistory.includes(newPasswordHash);
}
