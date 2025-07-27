/**
 * Trusted Devices Management Component
 * Allows users to view and manage their trusted devices
 * @author IdP System
 */

'use client';

import { useState, useEffect } from 'react';

/**
 * Trusted Devices component for device management
 * @returns {JSX.Element}
 */
export default function TrustedDevices() {
  const [devices, setDevices] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [currentSession, setCurrentSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionLoading, setActionLoading] = useState({});

  useEffect(() => {
    fetchDevices();
  }, []);

  /**
   * Fetch user's trusted devices and active sessions
   */
  const fetchDevices = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/devices', {
        method: 'GET',
        credentials: 'include'
      });

      const result = await response.json();

      if (!result.success) {
        setError(result.error || 'Failed to fetch devices');
        return;
      }

      setDevices(result.data.trustedDevices || []);
      setSessions(result.data.activeSessions || []);
      setCurrentSession(result.data.currentSession);
    } catch (err) {
      console.error('Error fetching devices:', err);
      setError('Failed to load device information');
    } finally {
      setLoading(false);
    }
  };

  /**
   * Remove a trusted device
   * @param {string} deviceId - Device ID to remove
   */
  const removeTrustedDevice = async (deviceId) => {
    try {
      setActionLoading(prev => ({ ...prev, [deviceId]: true }));

      const response = await fetch('/api/devices', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'remove-trusted-device',
          deviceId
        })
      });

      const result = await response.json();

      if (!result.success) {
        setError(result.error || 'Failed to remove device');
        return;
      }

      // Refresh device list
      await fetchDevices();
    } catch (err) {
      console.error('Error removing device:', err);
      setError('Failed to remove device');
    } finally {
      setActionLoading(prev => ({ ...prev, [deviceId]: false }));
    }
  };

  /**
   * Terminate a session
   * @param {string} sessionId - Session ID to terminate
   */
  const terminateSession = async (sessionId) => {
    try {
      setActionLoading(prev => ({ ...prev, [sessionId]: true }));

      const response = await fetch('/api/devices', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'terminate-session',
          sessionId
        })
      });

      const result = await response.json();

      if (!result.success) {
        setError(result.error || 'Failed to terminate session');
        return;
      }

      // Refresh sessions list
      await fetchDevices();
    } catch (err) {
      console.error('Error terminating session:', err);
      setError('Failed to terminate session');
    } finally {
      setActionLoading(prev => ({ ...prev, [sessionId]: false }));
    }
  };

  /**
   * Terminate all sessions except current
   */
  const terminateAllSessions = async () => {
    try {
      setActionLoading(prev => ({ ...prev, 'all-sessions': true }));

      const response = await fetch('/api/devices', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'terminate-all-sessions'
        })
      });

      const result = await response.json();

      if (!result.success) {
        setError(result.error || 'Failed to terminate sessions');
        return;
      }

      // Refresh sessions list
      await fetchDevices();
    } catch (err) {
      console.error('Error terminating all sessions:', err);
      setError('Failed to terminate all sessions');
    } finally {
      setActionLoading(prev => ({ ...prev, 'all-sessions': false }));
    }
  };

  /**
   * Remove all trusted devices
   */
  const removeAllTrustedDevices = async () => {
    try {
      setActionLoading(prev => ({ ...prev, 'all-devices': true }));

      const response = await fetch('/api/devices', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'remove-all-trusted-devices'
        })
      });

      const result = await response.json();

      if (!result.success) {
        setError(result.error || 'Failed to remove all devices');
        return;
      }

      // Refresh device list
      await fetchDevices();
    } catch (err) {
      console.error('Error removing all devices:', err);
      setError('Failed to remove all devices');
    } finally {
      setActionLoading(prev => ({ ...prev, 'all-devices': false }));
    }
  };

  /**
   * Format date for display
   * @param {string} dateString - ISO date string
   * @returns {string}
   */
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  /**
   * Extract device info from metadata or user agent
   * @param {Object} metadata - Device metadata object
   * @param {string} deviceName - Device name
   * @returns {string}
   */
  const getDeviceInfo = (metadata, deviceName) => {
    if (deviceName) return deviceName;
    
    const userAgent = metadata?.userAgent || '';
    if (!userAgent) return 'Unknown Device';
    
    if (userAgent.includes('iPhone')) return 'iPhone';
    if (userAgent.includes('iPad')) return 'iPad';
    if (userAgent.includes('Android')) return 'Android Device';
    if (userAgent.includes('Mac')) return 'Mac';
    if (userAgent.includes('Windows')) return 'Windows PC';
    if (userAgent.includes('Linux')) return 'Linux PC';
    
    return 'Unknown Device';
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
          <div className="animate-pulse">
            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4 mb-4"></div>
            <div className="space-y-3">
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded"></div>
              <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-5/6"></div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-red-50 dark:bg-red-900 border border-red-200 dark:border-red-800 rounded-md p-4">
          <div className="flex">
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800 dark:text-red-200">
                Error
              </h3>
              <div className="mt-2 text-sm text-red-700 dark:text-red-300">
                {error}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Trusted Devices */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border border-gray-200 dark:border-gray-700 rounded-lg">
        <div className="px-6 py-5 border-b border-gray-200 dark:border-gray-700">
          <div className="flex justify-between items-center">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
              Trusted Devices
            </h3>
            {devices.length > 0 && (
              <button
                onClick={removeAllTrustedDevices}
                disabled={actionLoading['all-devices']}
                className="inline-flex items-center px-3 py-2 border border-red-300 shadow-sm text-sm leading-4 font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed dark:border-red-600 dark:text-red-400 dark:bg-gray-800 dark:hover:bg-red-900"
              >
                {actionLoading['all-devices'] ? (
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                ) : null}
                Remove All
              </button>
            )}
          </div>
        </div>
        
        <div className="px-6 py-4">
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
            Devices you've marked as trusted won't require MFA verification for future logins.
          </p>

          {devices.length === 0 ? (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              No trusted devices yet. When you login from a new device, you can choose to trust it to skip MFA in the future.
            </p>
          ) : (
            <div className="space-y-4">
              {devices.map((device) => (
                <div key={device.id} className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <div className="flex-shrink-0">
                        <div className="h-8 w-8 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center">
                          <svg className="h-5 w-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                          </svg>
                        </div>
                      </div>
                      <div className="flex-1">
                        <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                          {getDeviceInfo(device.metadata, device.deviceName)}
                        </h4>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          Last seen: {formatDate(device.lastSeen)}
                        </p>
                        <p className="text-xs text-gray-400 dark:text-gray-500">
                          IP: {device.lastIP || device.firstIP || 'Unknown'} • Added: {formatDate(device.createdAt)}
                        </p>
                      </div>
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    <button
                      onClick={() => removeTrustedDevice(device.id)}
                      disabled={actionLoading[device.id]}
                      className="inline-flex items-center px-3 py-2 border border-red-300 shadow-sm text-sm leading-4 font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed dark:border-red-600 dark:text-red-400 dark:bg-gray-800 dark:hover:bg-red-900"
                    >
                      {actionLoading[device.id] ? (
                        <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                      ) : (
                        'Remove'
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Active Sessions */}
      <div className="bg-white dark:bg-gray-800 shadow-sm border border-gray-200 dark:border-gray-700 rounded-lg">
        <div className="px-6 py-5 border-b border-gray-200 dark:border-gray-700">
          <div className="flex justify-between items-center">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
              Active Sessions
            </h3>
            {sessions.length > 1 && (
              <button
                onClick={terminateAllSessions}
                disabled={actionLoading['all-sessions']}
                className="inline-flex items-center px-3 py-2 border border-red-300 shadow-sm text-sm leading-4 font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed dark:border-red-600 dark:text-red-400 dark:bg-gray-800 dark:hover:bg-red-900"
              >
                {actionLoading['all-sessions'] ? (
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                ) : null}
                End All Others
              </button>
            )}
          </div>
        </div>
        
        <div className="px-6 py-4">
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
            These are your currently active login sessions across different devices and browsers.
          </p>

          <div className="space-y-4">
            {/* Current Session */}
            {currentSession && (
              <div className="flex items-center justify-between p-4 border-2 border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900 rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <div className="flex-shrink-0">
                      <div className="h-8 w-8 bg-green-100 dark:bg-green-900 rounded-full flex items-center justify-center">
                        <svg className="h-5 w-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                      </div>
                    </div>
                    <div className="flex-1">
                      <h4 className="text-sm font-medium text-green-900 dark:text-green-100">
                        {getDeviceInfo({ userAgent: currentSession.userAgent }, null)} (Current Session)
                      </h4>
                      <p className="text-sm text-green-700 dark:text-green-300">
                        IP: {currentSession.ipAddress}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="flex-shrink-0">
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-200">
                    Current
                  </span>
                </div>
              </div>
            )}

            {/* Other Sessions */}
            {sessions.map((session) => {
              const isCurrentSession = currentSession && session.id === currentSession.id;
              if (isCurrentSession) return null;

              return (
                <div key={session.id} className="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <div className="flex-shrink-0">
                        <div className="h-8 w-8 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center">
                          <svg className="h-5 w-5 text-gray-600 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                          </svg>
                        </div>
                      </div>
                      <div className="flex-1">
                        <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                          {getDeviceInfo({ userAgent: session.userAgent }, null)}
                        </h4>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                          IP: {session.ipAddress}
                        </p>
                        <p className="text-xs text-gray-400 dark:text-gray-500">
                          Expires: {formatDate(session.expires)}
                        </p>
                      </div>
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    <button
                      onClick={() => terminateSession(session.id)}
                      disabled={actionLoading[session.id]}
                      className="inline-flex items-center px-3 py-2 border border-red-300 shadow-sm text-sm leading-4 font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed dark:border-red-600 dark:text-red-400 dark:bg-gray-800 dark:hover:bg-red-900"
                    >
                      {actionLoading[session.id] ? (
                        <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 714 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                      ) : (
                        'End Session'
                      )}
                    </button>
                  </div>
                </div>
              );
            })}

            {sessions.filter(s => !currentSession || s.id !== currentSession.id).length === 0 && (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                No other active sessions.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
