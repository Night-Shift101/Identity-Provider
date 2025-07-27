/**
 * Device Trust Prompt Component
 * Prompts users to trust their device during MFA verification
 * @author IdP System
 */

'use client';

import { useState } from 'react';
import { generateDeviceFingerprint, getDeviceDisplayName } from '@/lib/device-fingerprint';

/**
 * Device Trust Prompt component
 * @param {Object} props
 * @param {boolean} props.show - Whether to show the prompt
 * @param {Function} props.onDecision - Callback when user makes a decision
 * @returns {JSX.Element}
 */
export default function DeviceTrustPrompt({ show, onDecision }) {
  const [loading, setLoading] = useState(false);
  const [deviceName] = useState(getDeviceDisplayName());

  if (!show) return null;

  /**
   * Handle user's decision to trust or not trust the device
   * @param {boolean} trustDevice - Whether to trust the device
   */
  const handleDecision = async (trustDevice) => {
    if (!trustDevice) {
      onDecision({ trustDevice: false });
      return;
    }

    try {
      setLoading(true);
      
      // Generate device fingerprint
      const fingerprintResult = await generateDeviceFingerprint();
      
      if (!fingerprintResult.success) {
        console.error('Failed to generate device fingerprint:', fingerprintResult.error);
        onDecision({ trustDevice: false, error: 'Failed to generate device fingerprint' });
        return;
      }

      onDecision({ 
        trustDevice: true, 
        fingerprint: fingerprintResult.data,
        deviceName: deviceName
      });
    } catch (error) {
      console.error('Error handling device trust decision:', error);
      onDecision({ trustDevice: false, error: 'An unexpected error occurred' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white dark:bg-gray-800">
        <div className="mt-3">
          {/* Icon */}
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 dark:bg-blue-900">
            <svg className="h-6 w-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
            </svg>
          </div>

          {/* Title */}
          <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white text-center mt-4">
            Trust This Device?
          </h3>

          {/* Content */}
          <div className="mt-4 px-4">
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center mb-4">
              Would you like to trust <strong>{deviceName}</strong> for future logins?
            </p>
            
            <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-800 rounded-md p-3 mb-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd"></path>
                  </svg>
                </div>
                <div className="ml-3">
                  <h4 className="text-sm font-medium text-blue-800 dark:text-blue-200">
                    What does this mean?
                  </h4>
                  <div className="mt-1 text-sm text-blue-700 dark:text-blue-300">
                    <ul className="list-disc list-inside space-y-1">
                      <li>You won't need to verify MFA codes on this device</li>
                      <li>Only applies to this specific browser and device</li>
                      <li>You can remove this trust anytime in your security settings</li>
                    </ul>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-800 rounded-md p-3 mb-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd"></path>
                  </svg>
                </div>
                <div className="ml-3">
                  <h4 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                    Security Reminder
                  </h4>
                  <div className="mt-1 text-sm text-yellow-700 dark:text-yellow-300">
                    Only trust devices you personally own and control. Don't trust shared or public computers.
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Buttons */}
          <div className="flex space-x-3 mt-6">
            <button
              onClick={() => handleDecision(false)}
              disabled={loading}
              className="flex-1 inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed dark:border-gray-600 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
            >
              Don't Trust
            </button>
            <button
              onClick={() => handleDecision(true)}
              disabled={loading}
              className="flex-1 inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-blue-600 text-base font-medium text-white hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="flex items-center">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Processing...
                </div>
              ) : (
                'Trust Device'
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
