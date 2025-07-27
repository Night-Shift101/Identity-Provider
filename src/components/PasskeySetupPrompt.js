/**
 * Passkey Setup Prompt Component
 * Prompts users to set up passkeys on trusted devices
 * @author IdP System
 */

'use client';

import { useState } from 'react';

/**
 * PasskeySetupPrompt component
 * @param {Object} props
 * @param {boolean} props.isOpen - Whether the prompt is open
 * @param {Function} props.onClose - Function to close the prompt
 * @param {Function} props.onSetup - Function to start passkey setup
 * @param {Function} props.onSkip - Function to skip setup
 * @returns {JSX.Element}
 */
export default function PasskeySetupPrompt({ isOpen, onClose, onSetup, onSkip }) {
  const [isLoading, setIsLoading] = useState(false);

  if (!isOpen) return null;

  const handleSetup = async () => {
    setIsLoading(true);
    try {
      await onSetup();
    } catch (error) {
      // TODO: LOGGING - Use proper logging framework instead of console.error
      // TODO: UX - Add user-friendly error messages for different error types
      // TODO: ERROR_HANDLING - Handle specific WebAuthn error codes
      console.error('Passkey setup error:', error);
      
      if (error.name === 'NotAllowedError') {
        // User cancelled
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleSkip = () => {
    onSkip();
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-md mx-auto transform transition-all">
        <div className="p-6">
          {/* Icon */}
          <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-blue-100 mb-4">
            <svg className="h-8 w-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>

          {/* Content */}
          <div className="text-center">
            <h3 className="text-lg font-semibold text-black mb-2">
              Set up a passkey for faster sign-in
            </h3>
            <p className="text-sm text-gray-600 mb-6">
              Use your fingerprint, face, or device PIN to sign in securely without typing a password. This device appears to support passkeys.
            </p>

            {/* Benefits */}
            <div className="text-left bg-gray-50 rounded-lg p-4 mb-6">
              <h4 className="text-sm font-medium text-black mb-3">Benefits of passkeys:</h4>
              <ul className="space-y-2 text-sm text-gray-600">
                <li className="flex items-center">
                  <svg className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Faster sign-in with biometrics
                </li>
                <li className="flex items-center">
                  <svg className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  More secure than passwords
                </li>
                <li className="flex items-center">
                  <svg className="h-4 w-4 text-green-500 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  Protected against phishing
                </li>
              </ul>
            </div>
          </div>

          {/* Actions */}
          <div className="flex space-x-3">
            <button
              onClick={handleSkip}
              disabled={isLoading}
              className="flex-1 px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 border border-gray-300 rounded-lg hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Skip for now
            </button>
            <button
              onClick={handleSetup}
              disabled={isLoading}
              className="flex-1 px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center"
            >
              {isLoading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Setting up...
                </>
              ) : (
                'Set up passkey'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
