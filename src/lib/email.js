/**
 * Email service utilities
 * Handles email sending for authentication, security notifications, and account management
 * @author IdP System
 */

import nodemailer from 'nodemailer';
import { validateEmailConfig, isProduction, getSafeConfig } from '@/lib/config-validation';
import { checkRateLimit, recordRateLimitAttempt } from '@/lib/rate-limit';
import { ERROR_CODES, createErrorResponse, createSuccessResponse } from '@/lib/error-codes';

// Validate email configuration on module load
const emailConfigValidation = validateEmailConfig();
if (!emailConfigValidation.success) {
  console.error('Email service configuration error:', emailConfigValidation.error);
  if (isProduction()) {
    throw new Error(`Email service misconfigured: ${emailConfigValidation.error}`);
  }
}

// Get safe configuration
const config = getSafeConfig();

/**
 * Create email transporter with validated configuration and security options
 * @returns {{ success: boolean, error: string|null, data?: Object }} Structured response with transporter
 * @author IdP System
 */
function createTransporter() {
  try {
    // Re-validate configuration to ensure it's still valid
    const validation = validateEmailConfig();
    if (!validation.success) {
      return {
        success: false,
        error: `Email configuration invalid: ${validation.error}`,
        data: null
      };
    }

    const transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT, 10),
      secure: parseInt(process.env.SMTP_PORT, 10) === 465, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
      // Security options
      requireTLS: true,
      tls: {
        rejectUnauthorized: isProduction(), // Only reject in production
        minVersion: 'TLSv1.2'
      },
      // Connection limits for anti-spam
      pool: true,
      maxConnections: 3,
      maxMessages: 100,
      // Timeout settings
      connectionTimeout: 30000, // 30 seconds
      greetingTimeout: 30000,
      socketTimeout: 60000
    });

    return {
      success: true,
      error: null,
      data: transporter
    };
  } catch (error) {
    console.error('Transporter creation error:', error);
    return {
      success: false,
      error: 'Failed to create email transporter',
      data: null
    };
  }
}

/**
 * Sanitize email content to prevent XSS and injection attacks
 * @param {string} content - Raw content to sanitize
 * @returns {string} Sanitized content safe for email templates
 * @author IdP System
 */
function sanitizeEmailContent(content) {
  if (!content || typeof content !== 'string') {
    return '';
  }
  
  // Basic HTML entity encoding for security
  return content
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Check email rate limits before sending
 * @param {string} recipientEmail - Email address of recipient
 * @param {string} senderIP - IP address of sender for rate limiting
 * @returns {{ success: boolean, error: string|null }} Rate limit check result
 * @author IdP System
 */
function checkEmailRateLimit(recipientEmail, senderIP) {
  // Check IP-based rate limit
  const ipLimit = checkRateLimit('EMAIL_SEND_PER_IP', senderIP);
  if (!ipLimit.success) {
    return ipLimit;
  }
  
  // Check recipient-based rate limit
  const emailLimit = checkRateLimit('EMAIL_SEND_PER_EMAIL', recipientEmail);
  if (!emailLimit.success) {
    return emailLimit;
  }
  
  return { success: true, error: null };
}

/**
 * Record email sending attempt for rate limiting tracking
 * @param {string} recipientEmail - Email address of recipient
 * @param {string} senderIP - IP address of sender
 * @author IdP System
 */
function recordEmailAttempt(recipientEmail, senderIP) {
  recordRateLimitAttempt('EMAIL_SEND_PER_IP', senderIP);
  recordRateLimitAttempt('EMAIL_SEND_PER_EMAIL', recipientEmail);
}

/**
 * Send email verification with rate limiting and security measures
 * @param {string} email - Recipient email address
 * @param {string} verificationToken - Verification token
 * @param {string} [firstName] - User's first name for personalization
 * @param {string} [senderIP] - IP address of sender for rate limiting
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 * @author IdP System
 */
export async function sendEmailVerification(email, verificationToken, firstName, senderIP = '127.0.0.1') {
  try {
    // Check rate limits first
    const rateLimitCheck = checkEmailRateLimit(email, senderIP);
    if (!rateLimitCheck.success) {
      return rateLimitCheck;
    }

    // Create transporter with validation
    const transporterResult = createTransporter();
    if (!transporterResult.success) {
      recordEmailAttempt(email, senderIP);
      return transporterResult;
    }

    const transporter = transporterResult.data;
    
    // Use validated configuration
    const appName = sanitizeEmailContent(config.appName);
    const appUrl = config.appUrl;
    const sanitizedFirstName = firstName ? sanitizeEmailContent(firstName.trim()) : '';
    const sanitizedEmail = email.trim().toLowerCase();
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      recordEmailAttempt(email, senderIP);
      return {
        success: false,
        error: 'Invalid email format',
        data: null
      };
    }

    const verificationUrl = `${appUrl}/auth/verify-email?token=${encodeURIComponent(verificationToken)}`;
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: sanitizedEmail,
      subject: `Verify your ${appName} account`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Verify Your Email</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 28px;">${appName}</h1>
          </div>
          
          <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
            <h2 style="color: #495057; margin-top: 0;">Welcome${sanitizedFirstName ? `, ${sanitizedFirstName}` : ''}!</h2>
            
            <p>Thank you for creating an account with ${appName}. To complete your registration, please verify your email address by clicking the button below:</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationUrl}" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Verify Email Address</a>
            </div>
            
            <p style="color: #6c757d; font-size: 14px;">If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #007bff; font-size: 14px;">${verificationUrl}</p>
            
            <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
            
            <p style="color: #6c757d; font-size: 12px; margin: 0;">
              This verification link will expire in 24 hours. If you didn't create an account with ${appName}, you can safely ignore this email.
            </p>
          </div>
        </body>
        </html>
      `
    };

    const info = await transporter.sendMail(mailOptions);

    // Record successful email send for rate limiting
    recordEmailAttempt(email, senderIP);

    return {
      success: true,
      error: null,
      data: { 
        messageId: info.messageId,
        accepted: info.accepted,
        rejected: info.rejected
      }
    };
  } catch (err) {
    console.error('Email verification sending error:', err);
    recordEmailAttempt(email, senderIP);
    
    return {
      success: false,
      error: err?.message || 'Failed to send verification email',
      data: null
    };
  }
}

/**
 * Send password reset email with rate limiting and security measures
 * @param {string} email - Recipient email address
 * @param {string} resetToken - Password reset token
 * @param {string} [firstName] - User's first name for personalization
 * @param {string} [senderIP] - IP address of sender for rate limiting
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 * @author IdP System
 */
export async function sendPasswordReset(email, resetToken, firstName, senderIP = '127.0.0.1') {
  try {
    // Check rate limits first
    const rateLimitCheck = checkEmailRateLimit(email, senderIP);
    if (!rateLimitCheck.success) {
      return rateLimitCheck;
    }

    // Create transporter with validation
    const transporterResult = createTransporter();
    if (!transporterResult.success) {
      recordEmailAttempt(email, senderIP);
      return transporterResult;
    }

    const transporter = transporterResult.data;
    
    // Use validated configuration
    const appName = sanitizeEmailContent(config.appName);
    const appUrl = config.appUrl;
    const sanitizedFirstName = firstName ? sanitizeEmailContent(firstName.trim()) : '';
    const sanitizedEmail = email.trim().toLowerCase();
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      recordEmailAttempt(email, senderIP);
      return {
        success: false,
        error: 'Invalid email format',
        data: null
      };
    }

    const resetUrl = `${appUrl}/auth/reset-password?token=${encodeURIComponent(resetToken)}`;
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: sanitizedEmail,
      subject: `Reset your ${appName} password`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Reset Your Password</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 28px;">${appName}</h1>
          </div>
          
          <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
            <h2 style="color: #495057; margin-top: 0;">Password Reset Request</h2>
            
            <p>Hello${sanitizedFirstName ? `, ${sanitizedFirstName}` : ''},</p>
            <p>We received a request to reset your password for your ${appName} account. Click the button below to set a new password:</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetUrl}" style="background: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Reset Password</a>
            </div>
            
            <p style="color: #6c757d; font-size: 14px;">If the button doesn't work, you can copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #dc3545; font-size: 14px;">${resetUrl}</p>
            
            <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
            
            <p style="color: #6c757d; font-size: 12px; margin: 0;">
              This password reset link will expire in 1 hour. If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.
            </p>
          </div>
        </body>
        </html>
      `
    };

    const info = await transporter.sendMail(mailOptions);

    return {
      success: true,
      error: null,
      data: { messageId: info.messageId }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Email sending failed',
      data: null
    };
  }
}

/**
 * Send security alert email with rate limiting and security measures
 * @param {string} email - Recipient email address
 * @param {Object} alertData - Security alert information
 * @param {string} [senderIP] - IP address of sender for rate limiting
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 * @author IdP System
 */
export async function sendSecurityAlert(email, alertData, senderIP = '127.0.0.1') {
  try {
    // Check rate limits first
    const rateLimitCheck = checkEmailRateLimit(email, senderIP);
    if (!rateLimitCheck.success) {
      return rateLimitCheck;
    }

    // Create transporter with validation
    const transporterResult = createTransporter();
    if (!transporterResult.success) {
      recordEmailAttempt(email, senderIP);
      return transporterResult;
    }

    const transporter = transporterResult.data;
    
    // Use validated configuration and sanitize inputs
    const appName = sanitizeEmailContent(config.appName);
    const appUrl = config.appUrl;
    const sanitizedEmail = email.trim().toLowerCase();
    const sanitizedTitle = sanitizeEmailContent(alertData.title || 'Security Alert');
    const sanitizedMessage = sanitizeEmailContent(alertData.message || 'Suspicious activity detected');
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(sanitizedEmail)) {
      recordEmailAttempt(email, senderIP);
      return {
        success: false,
        error: 'Invalid email format',
        data: null
      };
    }
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: sanitizedEmail,
      subject: `Security Alert - ${appName}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Security Alert</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 28px;">🔒 Security Alert</h1>
          </div>
          
          <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
            <h2 style="color: #495057; margin-top: 0;">${alertData.title}</h2>
            
            <p>${alertData.message}</p>
            
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
              <h4 style="color: #856404; margin-top: 0;">Activity Details:</h4>
              <ul style="color: #856404; margin: 10px 0;">
                ${alertData.location ? `<li><strong>Location:</strong> ${alertData.location}</li>` : ''}
                ${alertData.device ? `<li><strong>Device:</strong> ${alertData.device}</li>` : ''}
                ${alertData.ipAddress ? `<li><strong>IP Address:</strong> ${alertData.ipAddress}</li>` : ''}
                ${alertData.timestamp ? `<li><strong>Time:</strong> ${alertData.timestamp}</li>` : ''}
              </ul>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${appUrl}/account/security" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Review Account Security</a>
            </div>
            
            <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
            
            <p style="color: #6c757d; font-size: 12px; margin: 0;">
              If this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately by changing your password and reviewing your security settings.
            </p>
          </div>
        </body>
        </html>
      `
    };

    const info = await transporter.sendMail(mailOptions);

    return {
      success: true,
      error: null,
      data: { messageId: info.messageId }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Email sending failed',
      data: null
    };
  }
}

/**
 * Send login notification email
 * @param {string} email - Recipient email
 * @param {Object} loginData - Login data
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function sendLoginNotification(email, loginData) {
  try {
    const transporter = createTransporter();
    const appName = process.env.APP_NAME || 'Identity Provider';
    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: `New login to your ${appName} account`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>New Login Notification</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 28px;">🔐 New Login</h1>
          </div>
          
          <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
            <h2 style="color: #495057; margin-top: 0;">Account Access Notification</h2>
            
            <p>Your ${appName} account was recently accessed from a new device or location.</p>
            
            <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
              <h4 style="color: #155724; margin-top: 0;">Login Details:</h4>
              <ul style="color: #155724; margin: 10px 0;">
                ${loginData.location ? `<li><strong>Location:</strong> ${loginData.location}</li>` : ''}
                ${loginData.device ? `<li><strong>Device:</strong> ${loginData.device}</li>` : ''}
                ${loginData.ipAddress ? `<li><strong>IP Address:</strong> ${loginData.ipAddress}</li>` : ''}
                ${loginData.timestamp ? `<li><strong>Time:</strong> ${loginData.timestamp}</li>` : ''}
              </ul>
            </div>
            
            <p>If this was you, you can ignore this email. If you don't recognize this activity, please secure your account immediately.</p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${appUrl}/account/security" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Secure My Account</a>
            </div>
            
            <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">
            
            <p style="color: #6c757d; font-size: 12px; margin: 0;">
              You're receiving this email to help keep your account secure. If you want to stop receiving these notifications, you can change your email preferences in your account settings.
            </p>
          </div>
        </body>
        </html>
      `
    };

    const info = await transporter.sendMail(mailOptions);

    return {
      success: true,
      error: null,
      data: { messageId: info.messageId }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Email sending failed',
      data: null
    };
  }
}

/**
 * Test email configuration
 * @returns {Promise<{success: boolean, error: string|null, data: Object|null}>}
 */
export async function testEmailConfiguration() {
  try {
    const transporter = createTransporter();
    await transporter.verify();

    return {
      success: true,
      error: null,
      data: { status: 'Email configuration is valid' }
    };
  } catch (err) {
    return {
      success: false,
      error: err?.message || 'Email configuration test failed',
      data: null
    };
  }
}
