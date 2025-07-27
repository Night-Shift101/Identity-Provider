/**
 * Multi-Factor Authentication Page Component
 * TOTP verification for secure login
 * @author IdP System
 */

'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import DeviceTrustPrompt from '@/components/DeviceTrustPrompt';

export default function MfaPage() {
  const router = useRouter();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [code, setCode] = useState(['', '', '', '', '', '']);
  const [backupCode, setBackupCode] = useState('');
  const [isBackupMode, setIsBackupMode] = useState(false);
  const [sessionData, setSessionData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showDeviceTrust, setShowDeviceTrust] = useState(false);
  const [mfaCompleted, setMfaCompleted] = useState(false);
  const inputRefs = useRef([]);

  useEffect(() => {
    // SECURITY FIX: Use secure server-side MFA session instead of sessionStorage
    const validateMfaSession = async () => {
      try {
        const response = await fetch('/api/auth/mfa/session', {
          method: 'GET',
          credentials: 'include' // Include HTTP-only cookies
        });

        const result = await response.json();

        if (!result.success) {
          // No valid MFA session - redirect to login
          router.push('/auth/login');
          return;
        }

        setSessionData(result.data);
        setLoading(false);
      } catch (error) {
        console.error('MFA session validation error:', error);
        router.push('/auth/login');
      }
    };

    validateMfaSession();
  }, [router]);

  const handleInputChange = (index, value) => {
    if (value.length > 1) return; // Only allow single digit
    
    const newCode = [...code];
    newCode[index] = value;
    setCode(newCode);

    // Auto-focus next input
    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }

    // Auto-submit when all fields are filled
    if (newCode.every(digit => digit !== '') && value) {
      handleSubmit(null, newCode.join(''));
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !code[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handlePaste = (e) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData('text').replace(/\D/g, '');
    if (pastedData.length === 6) {
      const newCode = pastedData.split('');
      setCode(newCode);
      handleSubmit(null, pastedData);
    }
  };

    const handleSubmit = async (e, codeValue = null) => {
    if (e) e.preventDefault();
    
    const mfaCode = codeValue || (isBackupMode ? backupCode : code.join(''));
    
    if (isBackupMode) {
      if (!mfaCode || mfaCode.length < 8) {
        setError('Please enter a valid backup code');
        return;
      }
    } else {
      if (mfaCode.length !== 6) {
        setError('Please enter a 6-digit code');
        return;
      }
    }

    if (!sessionData) {
      setError('Session expired. Please login again.');
      router.push('/auth/login');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include', // Include secure MFA session cookie
        body: JSON.stringify({
          code: mfaCode,
          sessionId: sessionData.sessionId
        })
      });

      const result = await response.json();

      if (result.success) {
        // MFA verification successful - show device trust prompt
        setMfaCompleted(true);
        setShowDeviceTrust(true);
      } else {
        // Extract error message whether it's a string or object
        const errorMessage = typeof result.error === 'string' 
          ? result.error 
          : result.error?.message || 'Invalid verification code';
        setError(errorMessage);
        
        if (isBackupMode) {
          setBackupCode('');
        } else {
          setCode(['', '', '', '', '', '']);
          inputRefs.current[0]?.focus();
        }
      }
    } catch (error) {
      console.error('MFA verification error:', error);
      setError('Verification failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Handle device trust decision after successful MFA
   * @param {Object} decision - User's decision about device trust
   */
  const handleDeviceTrustDecision = async (decision) => {
    try {
      if (decision.trustDevice && decision.fingerprint) {
        // Send device trust request to server
        const response = await fetch('/api/devices/check-trust', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            deviceFingerprint: decision.fingerprint,
            deviceName: decision.deviceName,
            metadata: {
              trusted: true,
              trustedAt: new Date().toISOString()
            }
          })
        });

        const result = await response.json();
        
        if (!result.success) {
          console.error('Failed to register trusted device:', result.error);
          // Continue anyway - device trust is optional
        }
      }

      // Redirect to dashboard regardless of device trust decision
      router.push('/dashboard');
    } catch (error) {
      console.error('Error handling device trust decision:', error);
      // Continue anyway - device trust is optional
      router.push('/dashboard');
    }
  };

  // Show loading state while validating MFA session
  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-white py-8 px-4 shadow-xl sm:rounded-lg sm:px-10">
            <div className="flex items-center justify-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              <span className="ml-3 text-gray-600">Validating session...</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

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
          Two-Factor Authentication
        </h2>
        <p className="mt-2 text-center text-sm text-gray-600">
          {isBackupMode 
            ? 'Enter your backup code'
            : 'Enter the 6-digit code from your authenticator app'
          }
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow-xl sm:rounded-lg sm:px-10">
          {error && (
            <div className="mb-6 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md">
              {typeof error === 'string' ? error : error.message || 'An error occurred'}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-3 text-center">
                {isBackupMode ? 'Backup Code' : 'Authentication Code'}
              </label>
              
              {isBackupMode ? (
                // Backup code input
                <div className="flex justify-center">
                  <input
                    type="text"
                    placeholder="Enter backup code"
                    value={backupCode}
                    onChange={(e) => setBackupCode(e.target.value)}
                    className="w-64 h-12 text-center text-lg font-mono border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    disabled={isLoading}
                    autoFocus
                  />
                </div>
              ) : (
                // 6-digit TOTP input
                <div className="flex justify-center space-x-3">
                  {code.map((digit, index) => (
                    <input
                      key={index}
                      ref={el => inputRefs.current[index] = el}
                      type="text"
                      inputMode="numeric"
                      pattern="\d*"
                      maxLength="1"
                      value={digit}
                      onChange={(e) => handleInputChange(index, e.target.value)}
                      onKeyDown={(e) => handleKeyDown(index, e)}
                      onPaste={handlePaste}
                      className="w-12 h-12 text-center text-xl font-semibold border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      disabled={isLoading}
                    />
                  ))}
                </div>
              )}
              
              <p className="mt-2 text-xs text-gray-500 text-center">
                {isBackupMode 
                  ? 'Enter one of your saved backup codes'
                  : 'Enter the code from Google Authenticator, Authy, or your preferred TOTP app'
                }
              </p>
            </div>

            <button
              type="submit"
              disabled={isLoading || (isBackupMode ? !backupCode : code.some(digit => digit === ''))}
              className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              ) : null}
              Verify {isBackupMode ? 'Backup Code' : 'Code'}
            </button>
          </form>

          {/* Toggle between TOTP and backup code modes */}
          <div className="mt-4 text-center">
            <button
              type="button"
              onClick={() => {
                setIsBackupMode(!isBackupMode);
                setError('');
                // Clear form data when switching modes
                if (isBackupMode) {
                  setBackupCode('');
                } else {
                  setCode(['', '', '', '', '', '']);
                }
              }}
              className="text-sm text-blue-600 hover:text-blue-500 underline"
            >
              {isBackupMode 
                ? 'Use authenticator app instead' 
                : 'Use backup code instead'
              }
            </button>
          </div>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300" />
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">Having trouble?</span>
              </div>
            </div>

            <div className="mt-6">
              <button
                type="button"
                onClick={() => {
                  sessionStorage.removeItem('mfaSession');
                  router.push('/auth/login');
                }}
                className="w-full text-center text-sm text-gray-600 hover:text-gray-500"
              >
                Back to login
              </button>
            </div>
          </div>

          <div className="mt-6 bg-blue-50 border border-blue-200 rounded-md p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-blue-800">
                  Security Tip
                </h3>
                <div className="mt-1 text-sm text-blue-700">
                  <p>
                    This extra step helps protect your account. The code refreshes every 30 seconds.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Device Trust Prompt */}
      <DeviceTrustPrompt 
        show={showDeviceTrust && mfaCompleted}
        onDecision={handleDeviceTrustDecision}
      />
    </div>
  );
}
