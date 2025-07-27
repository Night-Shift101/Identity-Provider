/**
 * User Login API Route
 * Handles user authentication with security monitoring and MFA support
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { verifyPassword, generateAccessToken, generateSecureToken } from '@/lib/auth';
import { userDb, sessionDb, activityDb } from '@/lib/database';
import { checkSuspiciousActivity, createDeviceFingerprint, checkTrustedDevice, logSecurityEvent, addTrustedDevice } from '@/lib/security';
import { sendLoginNotification, sendSecurityAlert } from '@/lib/email';
import { verifyTotpToken, verifyBackupCode } from '@/lib/mfa';
import { ERROR_CODES, createErrorResponse, createSuccessResponse } from '@/lib/error-codes';
import { checkRateLimit, recordRateLimitAttempt, resetRateLimit, getClientIP, getClientIPInfo } from '@/lib/rate-limit';

export async function POST(request) {
  try {
    // Get client IP with validation for rate limiting
    const clientIPInfo = getClientIPInfo(request);
    const clientIP = clientIPInfo.ip;

    const { 
      email, 
      password, 
      totpToken, 
      backupCode,
      rememberDevice = false,
      deviceFingerprint 
    } = await request.json();

    // Input validation and sanitization
    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_MISSING_FIELDS),
        { status: 400 }
      );
    }

    // Sanitize email and validate format
    const sanitizedEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizedEmail)) {
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_INVALID_EMAIL),
        { status: 400 }
      );
    }

    // Rate limiting - Check IP-based rate limit
    const ipRateLimit = checkRateLimit('LOGIN_ATTEMPTS_PER_IP', clientIP);
    if (!ipRateLimit.success) {
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.RATE_LIMIT_EXCEEDED, ipRateLimit.error),
        { 
          status: 429,
          headers: {
            'Retry-After': ipRateLimit.data?.retryAfter?.toString() || '60'
          }
        }
      );
    }

    // Rate limiting - Check email-based rate limit
    const emailRateLimit = checkRateLimit('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
    if (!emailRateLimit.success) {
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.RATE_LIMIT_EXCEEDED, emailRateLimit.error),
        { 
          status: 429,
          headers: {
            'Retry-After': emailRateLimit.data?.retryAfter?.toString() || '60'
          }
        }
      );
    }

    // Validate optional parameters
    if (totpToken && (typeof totpToken !== 'string' || !/^\d{6}$/.test(totpToken))) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_IP', clientIP);
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_INVALID_TOTP),
        { status: 400 }
      );
    }

    if (backupCode && (typeof backupCode !== 'string' || !/^[a-zA-Z0-9]{8}$/.test(backupCode))) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_IP', clientIP);
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_INVALID_BACKUP_CODE),
        { status: 400 }
      );
    }

    // Validate required fields
    if (!sanitizedEmail || !password) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_IP', clientIP);
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_MISSING_FIELDS),
        { status: 400 }
      );
    }

    // Get client information with validated and sanitized IP headers
    const clientIp = clientIPInfo.ip;
    const ipTrusted = clientIPInfo.trusted;
    const ipSource = clientIPInfo.source;
    const userAgent = request.headers.get('user-agent') || '';

    // Log IP validation info for security monitoring
    if (!ipTrusted && process.env.NODE_ENV === 'production') {
      console.warn('Untrusted IP source detected:', {
        ip: clientIp,
        source: ipSource,
        userAgent: userAgent.substring(0, 100) // Truncate for logging
      });
    }

    // Find user
    const userResult = await userDb.findByEmail(sanitizedEmail);
    if (!userResult.success || !userResult.data) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_IP', clientIP);
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
      
      // Log failed login attempt
      await logSecurityEvent({
        event: 'login_failed',
        details: { email: sanitizedEmail, reason: 'user_not_found' },
        ipAddress: clientIp,
        userAgent
      });

      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_INVALID_CREDENTIALS),
        { status: 401 }
      );
    }

    const user = userResult.data;

    // Check if user is active
    if (!user.isActive) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_IP', clientIP);
      recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
      
      await logSecurityEvent({
        userId: user.id,
        event: 'login_blocked',
        details: { reason: 'account_inactive' },
        ipAddress: clientIp,
        userAgent
      });

      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_ACCOUNT_DISABLED),
        { status: 403 }
      );
    }

    // Verify password
    if (user.password) {
      const passwordResult = await verifyPassword(password, user.password);
      if (!passwordResult.success || !passwordResult.data) {
        // Record failed attempt for rate limiting
        recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_IP', clientIP);
        recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
        
        // Log failed login attempt
        await logSecurityEvent({
          userId: user.id,
          event: 'login_failed',
          details: { reason: 'invalid_password' },
          ipAddress: clientIp,
          userAgent
        });

        return NextResponse.json(
          createErrorResponse(ERROR_CODES.AUTH_PASSWORD_INCORRECT),
          { status: 401 }
        );
      }
    }

    // Check for suspicious activity
    const suspiciousCheck = await checkSuspiciousActivity(user.id, clientIp, userAgent);
    const isSuspicious = suspiciousCheck.success && suspiciousCheck.data.isSuspicious;

    // Create device fingerprint
    const deviceFP = deviceFingerprint || createDeviceFingerprint(userAgent, clientIp).data;
    
    // Check if device is trusted
    const trustedDeviceCheck = await checkTrustedDevice(user.id, deviceFP);
    const isTrustedDevice = trustedDeviceCheck.success && trustedDeviceCheck.data;

    // Determine if MFA is required
    const requireMFA = user.mfaEnabled && (!isTrustedDevice || isSuspicious);

    if (requireMFA) {
      // Verify MFA token if provided
      if (totpToken || backupCode) {
        let mfaValid = false;

        if (totpToken && user.mfaSecret) {
          const totpResult = await verifyTotpToken(totpToken, user.mfaSecret);
          mfaValid = totpResult.success && totpResult.data;
        } else if (backupCode && user.mfaBackupCodes) {
          const backupResult = verifyBackupCode(backupCode, user.mfaBackupCodes);
          if (backupResult.success && backupResult.data.isValid) {
            mfaValid = true;
            
            // Update backup codes (remove used code)
            await userDb.update(user.id, {
              mfaBackupCodes: backupResult.data.remainingCodes
            });
          }
        }

        if (!mfaValid) {
          // Record failed attempt for rate limiting
          recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_IP', clientIP);
          recordRateLimitAttempt('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);
          
          await logSecurityEvent({
            userId: user.id,
            event: 'mfa_failed',
            details: { method: totpToken ? 'totp' : 'backup_code' },
            ipAddress: clientIp,
            userAgent
          });

          return NextResponse.json(
            createErrorResponse(ERROR_CODES.AUTH_MFA_INVALID),
            { status: 401 }
          );
        }
      } else {
        // MFA required but not provided
        return NextResponse.json(
          { 
            success: false, 
            error: 'Multi-factor authentication required',
            requireMFA: true,
            isSuspicious,
            suspiciousFlags: suspiciousCheck.data?.flags || []
          },
          { status: 200 }
        );
      }
    }

    // Generate session token
    const sessionToken = generateSecureToken();
    // TODO: CONFIGURATION - Make session expiry configurable via environment variables (currently hardcoded 30 days)
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    // Create session
    const sessionResult = await sessionDb.create({
      sessionToken,
      userId: user.id,
      expires: expiresAt,
      ipAddress: clientIp,
      userAgent
    });

    if (!sessionResult.success) {
      return NextResponse.json(
        { success: false, error: 'Session creation failed' },
        { status: 500 }
      );
    }

    // Generate JWT access token
    const accessTokenResult = await generateAccessToken({
      userId: user.id,
      email: user.email,
      sessionId: sessionResult.data.id
    });

    if (!accessTokenResult.success) {
      return NextResponse.json(
        { success: false, error: 'Token generation failed' },
        { status: 500 }
      );
    }

    // Log successful login
    await activityDb.logActivity({
      userId: user.id,
      ipAddress: clientIp,
      userAgent,
      location: suspiciousCheck.data?.location ? 
        `${suspiciousCheck.data.location.city}, ${suspiciousCheck.data.location.country}` : null,
      country: suspiciousCheck.data?.location?.country || null,
      city: suspiciousCheck.data?.location?.city || null,
      success: true
    });

    // Update last login time
    await userDb.update(user.id, {
      lastLoginAt: new Date()
    });

    // Add device to trusted list if requested and MFA was successful
    if (rememberDevice && deviceFP && (requireMFA || !user.mfaEnabled)) {
      await addTrustedDevice({
        userId: user.id,
        deviceId: generateSecureToken(16),
        fingerprint: deviceFP,
        name: suspiciousCheck.data?.device ? 
          `${suspiciousCheck.data.device.browser} on ${suspiciousCheck.data.device.os}` : 
          'Unknown Device',
        userAgent,
        ipAddress: clientIp
      });
    }

    // Send notifications for suspicious activity
    if (isSuspicious && suspiciousCheck.data?.flags?.length > 0) {
      const location = suspiciousCheck.data.location ? 
        `${suspiciousCheck.data.location.city}, ${suspiciousCheck.data.location.country}` : 
        'Unknown Location';
      
      await sendSecurityAlert(user.email, {
        title: 'Suspicious Login Activity Detected',
        message: 'We detected unusual activity on your account. If this was you, you can ignore this email.',
        location,
        device: suspiciousCheck.data.device ? 
          `${suspiciousCheck.data.device.browser} on ${suspiciousCheck.data.device.os}` : 
          'Unknown Device',
        ipAddress: clientIp,
        timestamp: new Date().toLocaleString()
      });
    } else if (!isTrustedDevice) {
      // Send login notification for new device
      const location = suspiciousCheck.data?.location ? 
        `${suspiciousCheck.data.location.city}, ${suspiciousCheck.data.location.country}` : 
        'Unknown Location';
      
      await sendLoginNotification(user.email, {
        location,
        device: suspiciousCheck.data?.device ? 
          `${suspiciousCheck.data.device.browser} on ${suspiciousCheck.data.device.os}` : 
          'Unknown Device',
        ipAddress: clientIp,
        timestamp: new Date().toLocaleString()
      });
    }

    // Log successful login
    await logSecurityEvent({
      userId: user.id,
      event: 'login_success',
      details: {
        mfaUsed: requireMFA,
        deviceTrusted: !!isTrustedDevice,
        suspicious: isSuspicious
      },
      ipAddress: clientIp,
      userAgent
    });

    // Reset rate limits on successful authentication
    resetRateLimit('LOGIN_ATTEMPTS_PER_IP', clientIP);
    resetRateLimit('LOGIN_ATTEMPTS_PER_EMAIL', sanitizedEmail);

    // Prepare response
    const response = NextResponse.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
          isVerified: user.isVerified,
          mfaEnabled: user.mfaEnabled
        },
        accessToken: accessTokenResult.data,
        expiresAt: expiresAt.toISOString()
      }
    }, { status: 200 });

    // Set session cookie with enhanced security
    response.cookies.set('session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict', // Enhanced CSRF protection
      // TODO: CONFIGURATION - Make cookie maxAge configurable via environment variables (currently hardcoded 30 days)
      maxAge: 30 * 24 * 60 * 60 // 30 days
    });

    return response;

  } catch (error) {
    // TODO: SECURITY - Don't log sensitive information in production
    // TODO: LOGGING - Use proper logging framework instead of console.error
    // TODO: MONITORING - Add error tracking and alerting
    console.error('Login error:', error);
    
    return NextResponse.json(
      { success: false, error: 'Internal server error' },
      { status: 500 }
    );
  }
}
