/**
 * OAuth Account Linking API Route
 * Handles linking/unlinking OAuth providers (Google, GitHub, etc.)
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { userDb, prisma } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';
import { generatePKCEParams, generateOAuthState, validateOAuthState, verifyPKCE } from '@/lib/oauth-pkce';
import { checkRateLimit, recordRateLimitAttempt, getClientIPInfo } from '@/lib/rate-limit';
import { ERROR_CODES, createErrorResponse, createSuccessResponse } from '@/lib/error-codes';

// Temporary in-memory storage for PKCE parameters (in production, use Redis)
const pkceStore = new Map();

// Cleanup expired PKCE entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  const maxAge = 10 * 60 * 1000; // 10 minutes
  
  for (const [key, data] of pkceStore.entries()) {
    if (now - data.timestamp > maxAge) {
      pkceStore.delete(key);
    }
  }
}, 5 * 60 * 1000);

// OAuth Provider configurations
// TODO: SECURITY - Move OAuth credentials to secure configuration service
// TODO: SECURITY - Add OAuth state parameter validation to prevent CSRF
// TODO: SECURITY - Implement OAuth PKCE for enhanced security
const OAUTH_PROVIDERS = {
  google: {
    name: 'Google',
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
    scope: 'openid email profile'
  },
  github: {
    name: 'GitHub',
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    scope: 'user:email'
  }
};

export async function GET(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const userId = authResult.data.user.id;

    // Get linked OAuth accounts
    const linkedAccounts = await prisma.oAuthAccount.findMany({
      where: { userId },
      select: {
        id: true,
        provider: true,
        providerAccountId: true,
        createdAt: true
      }
    });

    return NextResponse.json({
      success: true,
      data: {
        linkedAccounts,
        availableProviders: Object.keys(OAUTH_PROVIDERS)
      }
    });

  } catch (error) {
    console.error('OAuth accounts fetch error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

export async function POST(request) {
  try {
    // Get client IP for rate limiting
    const clientIPInfo = getClientIPInfo(request);
    const clientIP = clientIPInfo.ip;

    // Rate limiting for OAuth operations
    const ipRateLimit = checkRateLimit('OAUTH_ATTEMPTS_PER_IP', clientIP);
    if (!ipRateLimit.success) {
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.RATE_LIMIT_EXCEEDED, ipRateLimit.error),
        { 
          status: 429,
          headers: {
            'Retry-After': ipRateLimit.data?.retryAfter?.toString() || '300'
          }
        }
      );
    }

    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('OAUTH_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_SESSION_EXPIRED, authResult.error || 'Authentication required'),
        { status: 401 }
      );
    }

    const { action, provider, code, state } = await request.json();

    if (!OAUTH_PROVIDERS[provider]) {
      // Record failed attempt for rate limiting
      recordRateLimitAttempt('OAUTH_ATTEMPTS_PER_IP', clientIP);
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.VALIDATION_MISSING_FIELDS, 'Unsupported OAuth provider'),
        { status: 400 }
      );
    }

    const userId = authResult.data.user.id;

    switch (action) {
      case 'get-auth-url':
        return await handleGetAuthUrl(provider, userId);
      
      case 'link-account':
        return await handleLinkAccount(provider, code, state, userId, request);
      
      case 'unlink-account':
        return await handleUnlinkAccount(provider, userId, request);
      
      default:
        return NextResponse.json({
          success: false,
          error: 'Invalid action'
        }, { status: 400 });
    }

  } catch (error) {
    console.error('OAuth linking error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

async function handleGetAuthUrl(provider, userId) {
  try {
    const config = OAUTH_PROVIDERS[provider];
    
    // Generate PKCE parameters for enhanced security
    const pkceParams = generatePKCEParams();
    
    // Generate secure state parameter
    const state = generateOAuthState({ 
      userId, 
      provider,
      action: 'link-account'
    });
    
    // Store PKCE parameters temporarily (keyed by state for retrieval)
    pkceStore.set(state, {
      codeVerifier: pkceParams.codeVerifier,
      codeChallenge: pkceParams.codeChallenge,
      userId,
      provider,
      timestamp: Date.now()
    });

    // Build authorization URL with PKCE parameters
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: `${process.env.APP_URL}/api/auth/oauth/callback`,
      response_type: 'code',
      scope: config.scope,
      state,
      code_challenge: pkceParams.codeChallenge,
      code_challenge_method: pkceParams.codeChallengeMethod
    });

    const authUrl = `${config.authUrl}?${params.toString()}`;

    return NextResponse.json({
      success: true,
      data: { authUrl }
    });

  } catch (error) {
    console.error('OAuth URL generation error:', error);
    return NextResponse.json(
      createErrorResponse(ERROR_CODES.SYSTEM_ERROR, 'Failed to generate auth URL'),
      { status: 500 }
    );
  }
}

async function handleLinkAccount(provider, code, state, userId, request) {
  try {
    // Get client IP for security logging
    const clientIPInfo = getClientIPInfo(request);
    
    // Validate state parameter with enhanced security
    const stateValidation = validateOAuthState(state);
    if (!stateValidation.success) {
      console.warn('OAuth state validation failed:', {
        error: stateValidation.error,
        ip: clientIPInfo.ip,
        provider
      });
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_TOKEN_INVALID, 'Invalid state parameter'),
        { status: 400 }
      );
    }

    const stateData = stateValidation.data;
    
    // Verify state data matches request
    if (stateData.userId !== userId || stateData.provider !== provider) {
      console.warn('OAuth state mismatch:', {
        expected: { userId, provider },
        received: { userId: stateData.userId, provider: stateData.provider },
        ip: clientIPInfo.ip
      });
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_TOKEN_INVALID, 'State validation failed'),
        { status: 400 }
      );
    }

    // Retrieve and verify PKCE parameters
    const pkceData = pkceStore.get(state);
    if (!pkceData) {
      console.warn('PKCE data not found for state:', {
        state: state.substring(0, 10) + '...',
        ip: clientIPInfo.ip,
        provider
      });
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.AUTH_TOKEN_INVALID, 'PKCE validation failed'),
        { status: 400 }
      );
    }

    // Clean up PKCE data immediately after retrieval
    pkceStore.delete(state);

    // Exchange code for access token with PKCE verification
    const config = OAUTH_PROVIDERS[provider];
    
    const tokenResponse = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: `${process.env.APP_URL}/api/auth/oauth/callback`,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code_verifier: pkceData.codeVerifier // PKCE verification
      })
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('OAuth token exchange failed:', {
        status: tokenResponse.status,
        error: errorText,
        provider,
        ip: clientIPInfo.ip
      });
      
      return NextResponse.json(
        createErrorResponse(ERROR_CODES.SYSTEM_ERROR, 'Failed to exchange authorization code'),
        { status: 400 }
      );
    }

    const tokenData = await tokenResponse.json();

    // Get user info from provider
    const userInfoResponse = await fetch(config.userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });

    if (!userInfoResponse.ok) {
      return NextResponse.json({
        success: false,
        error: 'Failed to fetch user info from provider'
      }, { status: 400 });
    }

    const userInfo = await userInfoResponse.json();
    const providerAccountId = userInfo.id || userInfo.login; // GitHub uses 'login'

    // Check if this OAuth account is already linked to another user
    const existingAccount = await prisma.oAuthAccount.findUnique({
      where: {
        provider_providerAccountId: {
          provider,
          providerAccountId: providerAccountId.toString()
        }
      }
    });

    if (existingAccount && existingAccount.userId !== userId) {
      return NextResponse.json({
        success: false,
        error: 'This account is already linked to another user'
      }, { status: 400 });
    }

    if (existingAccount && existingAccount.userId === userId) {
      return NextResponse.json({
        success: false,
        error: 'This account is already linked to your profile'
      }, { status: 400 });
    }

    // Create OAuth account link
    await prisma.oAuthAccount.create({
      data: {
        userId,
        provider,
        providerAccountId: providerAccountId.toString(),
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        expiresAt: tokenData.expires_in ? 
          new Date(Date.now() + tokenData.expires_in * 1000) : null,
        tokenType: tokenData.token_type || 'bearer',
        scope: tokenData.scope || config.scope
      }
    });

    // Log security event
    await logSecurityEvent({
      userId,
      event: 'oauth_account_linked',
      details: {
        provider,
        providerAccountId: providerAccountId.toString(),
        email: userInfo.email
      },
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || ''
    });

    return NextResponse.json({
      success: true,
      message: `${config.name} account linked successfully`,
      data: {
        provider,
        providerAccountId: providerAccountId.toString()
      }
    });

  } catch (error) {
    console.error('Link account error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to link account'
    }, { status: 500 });
  }
}

async function handleUnlinkAccount(provider, userId, request) {
  try {
    // Find and delete OAuth account
    const deletedAccount = await prisma.oAuthAccount.deleteMany({
      where: {
        userId,
        provider
      }
    });

    if (deletedAccount.count === 0) {
      return NextResponse.json({
        success: false,
        error: 'OAuth account not found'
      }, { status: 404 });
    }

    // Log security event
    await logSecurityEvent({
      userId,
      event: 'oauth_account_unlinked',
      details: {
        provider
      },
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || ''
    });

    return NextResponse.json({
      success: true,
      message: `${OAUTH_PROVIDERS[provider].name} account unlinked successfully`
    });

  } catch (error) {
    console.error('Unlink account error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to unlink account'
    }, { status: 500 });
  }
}
