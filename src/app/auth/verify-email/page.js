/**
 * Email Verification Page Component
 * Handles email verification from email links
 * @author IdP System
 */

'use client';

import { useState, useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';

export default function VerifyEmailPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [resending, setResending] = useState(false);

  useEffect(() => {
    const token = searchParams.get('token');
    if (token) {
      verifyEmail(token);
    } else {
      setError('Invalid verification link');
      setIsLoading(false);
    }
  }, [searchParams]);

  const verifyEmail = async (token) => {
    try {
      const response = await fetch('/api/auth/verify-email', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ token }),
      });

      const data = await response.json();

      if (!response.ok) {
        const errorMessage = typeof data.error === 'string' 
          ? data.error 
          : data.error?.message || 'Verification failed';
        setError(errorMessage);
        return;
      }

      setSuccess(true);
      
      // Redirect to login after success
      // TODO: UX - Add user control over auto-redirect timing
      // TODO: ACCESSIBILITY - Announce redirect to screen readers
      // TODO: CONFIGURATION - Make auto-redirect timeout configurable
      setTimeout(() => {
        router.push('/auth/login?verified=true');
      }, 3000);

    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const resendVerification = async () => {
    setResending(true);
    try {
      const email = searchParams.get('email');
      if (!email) {
        // TODO: UX - Replace alert() with proper toast notification system
        // TODO: SECURITY - Add input validation for email parameter
        alert('Please enter your email address');
        return;
      }

      const response = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });

      if (response.ok) {
        // TODO: UX - Replace alert() with proper toast notification system
        // TODO: ACCESSIBILITY - Add proper ARIA announcements for screen readers
        alert('Verification email sent! Please check your inbox.');
      } else {
        // TODO: UX - Replace alert() with proper error handling UI
        alert('Failed to send verification email. Please try again.');
      }
    } catch (err) {
      // TODO: UX - Replace alert() with proper error handling UI
      // TODO: LOGGING - Add proper error logging
      alert('Network error. Please try again.');
    } finally {
      setResending(false);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <div className="flex justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
          <h2 className="mt-6 text-center text-3xl font-bold text-black">
            Verifying your email...
          </h2>
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
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow-xl sm:rounded-lg sm:px-10">
          {success ? (
            <div className="text-center">
              <div className="flex justify-center">
                <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
              </div>
              <h2 className="mt-6 text-center text-3xl font-bold text-black">
                Email Verified!
              </h2>
              <p className="mt-2 text-center text-sm text-gray-600">
                Your email has been successfully verified. You can now sign in to your account.
              </p>
              <div className="mt-6">
                <Link
                  href="/auth/login"
                  className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Continue to Sign In
                </Link>
              </div>
            </div>
          ) : (
            <div className="text-center">
              <div className="flex justify-center">
                <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                </div>
              </div>
              <h2 className="mt-6 text-center text-3xl font-bold text-black">
                Verification Failed
              </h2>
              <div className="mt-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md">
                {typeof error === 'string' ? error : error.message || 'An error occurred'}
              </div>
              
              <div className="mt-6 space-y-4">
                <button
                  onClick={resendVerification}
                  disabled={resending}
                  className="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  {resending ? 'Sending...' : 'Resend Verification Email'}
                </button>
                
                <Link
                  href="/auth/login"
                  className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Back to Sign In
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Help Text */}
      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-blue-800">
                Need help?
              </h3>
              <div className="mt-1 text-sm text-blue-700">
                <p>
                  If you continue to have problems with email verification, please contact support.
                  Make sure to check your spam folder for verification emails.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
