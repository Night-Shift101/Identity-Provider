/**
 * Login Page Component
 * User authentication form with email/password and passkey suppo      // Start WebAuthn authentication
      const startResponse = await fetch('/api/auth/webauthn/authenticate/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!startResponse.ok) {
        throw new Error('Failed to start passkey authentication');
      }

      const startData = await startResponse.json();
      
      if (!startData.success) {
        throw new Error(startData.error || 'Failed to start passkey authentication');
      }

      const { challengeKey, challenge, allowCredentials } = startData; IdP System
 */

'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import PasskeySetupPrompt from '@/components/PasskeySetupPrompt';
import { 
  shouldPromptPasskeySetup, 
  updateDeviceTrust, 
  dismissPasskeyPrompt 
} from '@/lib/passkey-utils';

export default function LoginPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPasskeyPrompt, setShowPasskeyPrompt] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    rememberMe: false
  });

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handlePasswordLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: formData.email,
          password: formData.password,
          rememberMe: formData.rememberMe
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Login failed');
        return;
      }

      // Check if MFA is required
      if (data.requiresMfa) {
        // Use secure URL parameter instead of sessionStorage
        const mfaToken = encodeURIComponent(data.mfaToken || '');
        router.push(`/auth/mfa?token=${mfaToken}`);
        return;
      }

      // Update device trust
      updateDeviceTrust(true);

      // Check if we should prompt for passkey setup
      const shouldPrompt = await shouldPromptPasskeySetup();
      if (shouldPrompt) {
        setShowPasskeyPrompt(true);
      } else {
        // Successful login - go to dashboard
        router.push('/dashboard');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    setIsLoading(true);
    setError('');

    try {
      // Start WebAuthn authentication
      const startResponse = await fetch('/api/auth/webauthn/authenticate/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!startResponse.ok) {
        throw new Error('Failed to start passkey authentication');
      }

      const { challenge, allowCredentials, challengeKey } = await startResponse.json();

      // Helper function to convert base64url to Uint8Array
      const base64urlToUint8Array = (base64url) => {
        // Convert base64url to base64
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if necessary
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        return new Uint8Array(Buffer.from(padded, 'base64'));
      };

      // Create credential request options
      const credentialRequestOptions = {
        challenge: base64urlToUint8Array(challenge),
        allowCredentials: allowCredentials?.map(cred => ({
          ...cred,
          id: base64urlToUint8Array(cred.id)
        })) || [],
        userVerification: 'preferred',
        timeout: 60000
      };

      // Get credential from authenticator
      const credential = await navigator.credentials.get({
        publicKey: credentialRequestOptions
      });

      if (!credential) {
        throw new Error('No credential received');
      }

      // Helper function to convert Uint8Array to base64url
      const uint8ArrayToBase64url = (array) => {
        const base64 = btoa(String.fromCharCode(...array));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      };

      // Complete authentication
      const finishResponse = await fetch('/api/auth/webauthn/authenticate/finish', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          challengeKey,
          id: credential.id, // This is already base64url encoded
          rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
          response: {
            clientDataJSON: uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON)),
            authenticatorData: uint8ArrayToBase64url(new Uint8Array(credential.response.authenticatorData)),
            signature: uint8ArrayToBase64url(new Uint8Array(credential.response.signature)),
            userHandle: credential.response.userHandle ? uint8ArrayToBase64url(new Uint8Array(credential.response.userHandle)) : null
          },
          type: credential.type
        }),
      });

      const result = await finishResponse.json();

      if (!finishResponse.ok) {
        throw new Error(result.error || 'Passkey authentication failed');
      }

      // Successful passkey login
      router.push('/dashboard');
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        setError('Passkey authentication was cancelled or failed');
      } else if (err.name === 'NotSupportedError') {
        setError('Passkeys are not supported on this device');
      } else {
        setError(err.message || 'Passkey authentication failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasskeySetup = async () => {
    try {
      // Start passkey registration
      const startResponse = await fetch('/api/auth/passkeys/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ action: 'start' }),
      });

      if (!startResponse.ok) {
        throw new Error('Failed to start passkey registration');
      }

      const startData = await startResponse.json();
      if (!startData.success) {
        throw new Error(startData.error);
      }

      const options = startData.data;

      // Helper function to convert base64url to Uint8Array
      const base64urlToUint8Array = (base64url) => {
        // Convert base64url to base64
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        const padding = base64.length % 4;
        const paddedBase64 = padding ? base64 + '='.repeat(4 - padding) : base64;
        // Convert to Uint8Array
        return Uint8Array.from(atob(paddedBase64), c => c.charCodeAt(0));
      };

      // Convert challenge and user ID to Uint8Array
      const credentialCreationOptions = {
        ...options,
        challenge: base64urlToUint8Array(options.challenge),
        user: {
          ...options.user,
          id: base64urlToUint8Array(options.user.id)
        },
        excludeCredentials: options.excludeCredentials?.map(cred => ({
          ...cred,
          id: base64urlToUint8Array(cred.id)
        })) || []
      };

      // Helper function to convert Uint8Array to base64url
      const uint8ArrayToBase64url = (array) => {
        const base64 = btoa(String.fromCharCode(...array));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      };

      // Create credential
      const credential = await navigator.credentials.create({
        publicKey: credentialCreationOptions
      });

      if (!credential) {
        throw new Error('No credential created');
      }

      // Finish registration
      const finishResponse = await fetch('/api/auth/passkeys/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'finish',
          credentialName: 'My Device',
          registrationResponse: {
            id: credential.id,
            rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
            response: {
              clientDataJSON: uint8ArrayToBase64url(new Uint8Array(credential.response.clientDataJSON)),
              attestationObject: uint8ArrayToBase64url(new Uint8Array(credential.response.attestationObject))
            },
            type: credential.type
          }
        }),
      });

      const finishData = await finishResponse.json();
      if (!finishData.success) {
        throw new Error(finishData.error);
      }

      // Success - close prompt and go to dashboard
      setShowPasskeyPrompt(false);
      router.push('/dashboard');

    } catch (error) {
      console.error('Passkey setup error:', error);
      if (error.name === 'NotAllowedError') {
        // User cancelled - just close prompt
        setShowPasskeyPrompt(false);
        router.push('/dashboard');
      } else {
        setError('Failed to set up passkey: ' + error.message);
        setShowPasskeyPrompt(false);
        router.push('/dashboard');
      }
    }
  };

  const handleSkipPasskeySetup = () => {
    dismissPasskeyPrompt();
    setShowPasskeyPrompt(false);
    router.push('/dashboard');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="flex items-center">
            <div className="w-10 h-10 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
              <span className="text-white font-bold">IdP</span>
            </div>
            <span className="ml-3 text-2xl font-bold text-black">Identity Provider</span>
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-bold text-black">
          Sign in to your account
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          Or{' '}
          <Link href="/auth/register" className="font-medium text-blue-600 hover:text-blue-500">
            create a new account
          </Link>
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow-xl sm:rounded-lg sm:px-10">
          {error && (
            <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md">
              {error}
            </div>
          )}

          <form className="space-y-6" onSubmit={handlePasswordLogin}>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email address
              </label>
              <div className="mt-1">
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={formData.email}
                  onChange={handleInputChange}
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md placeholder-gray-400 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Enter your email"
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <div className="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={formData.password}
                  onChange={handleInputChange}
                  className="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md placeholder-gray-400 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Enter your password"
                />
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center">
                <input
                  id="rememberMe"
                  name="rememberMe"
                  type="checkbox"
                  checked={formData.rememberMe}
                  onChange={handleInputChange}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label htmlFor="rememberMe" className="ml-2 block text-sm text-black">
                  Remember me
                </label>
              </div>

              <div className="text-sm">
                <Link href="/auth/forgot-password" className="font-medium text-blue-600 hover:text-blue-500">
                  Forgot your password?
                </Link>
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                ) : null}
                Sign in with password
              </button>
            </div>
          </form>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">Or</span>
              </div>
            </div>

            <div className="mt-6">
              <button
                onClick={handlePasskeyLogin}
                disabled={isLoading}
                className="group relative w-full flex justify-center py-2 px-4 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                </svg>
                Sign in with passkey
              </button>
            </div>
          </div>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">Or continue with</span>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-2 gap-3">
              <button
                onClick={() => window.location.href = '/api/auth/oauth/google'}
                className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                <span className="ml-2">Google</span>
              </button>

              <button
                onClick={() => window.location.href = '/api/auth/oauth/github'}
                className="w-full inline-flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm bg-white text-sm font-medium text-gray-500 hover:bg-gray-50"
              >
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
                <span className="ml-2">GitHub</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Passkey Setup Prompt */}
      <PasskeySetupPrompt
        isOpen={showPasskeyPrompt}
        onClose={() => setShowPasskeyPrompt(false)}
        onSetup={handlePasskeySetup}
        onSkip={handleSkipPasskeySetup}
      />
    </div>
  );
}
