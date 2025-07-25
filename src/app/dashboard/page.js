/**
 * Dashboard Page Component
 * Main dashboard after successful authentication with inline editing
 * @author IdP System
 */

'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function DashboardPage() {
  const router = useRouter();
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  
  // Edit states for inline editing
  const [editingProfile, setEditingProfile] = useState(false);
  const [editingPassword, setEditingPassword] = useState(false);
  
  // Data state
  const [devices, setDevices] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [securityLogs, setSecurityLogs] = useState([]);
  const [passkeys, setPasskeys] = useState([]);
  
  // Form state for profile editing
  const [profileForm, setProfileForm] = useState({
    firstName: '',
    lastName: '',
    email: '',
    username: ''
  });

  // Password change form
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  // Loading states
  const [isUpdatingProfile, setIsUpdatingProfile] = useState(false);
  const [isChangingPassword, setIsChangingPassword] = useState(false);
  const [isRemovingDevice, setIsRemovingDevice] = useState(null);
  const [isTerminatingSession, setIsTerminatingSession] = useState(null);

  useEffect(() => {
    fetchUserProfile();
    fetchDevices();
    fetchSessions();
    fetchSecurityLogs();
    fetchPasskeys();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const response = await fetch('/api/auth/profile');
      if (!response.ok) {
        if (response.status === 401) {
          router.push('/auth/login');
          return;
        }
        throw new Error('Failed to fetch profile');
      }
      
      const result = await response.json();
      
      if (result.success && result.data.user) {
        const userData = result.data.user;
        setUser(userData);
        
        // Initialize profile form with user data
        setProfileForm({
          firstName: userData.firstName || '',
          lastName: userData.lastName || '',
          email: userData.email || '',
          username: userData.username || ''
        });
      } else {
        throw new Error(result.error || 'Failed to fetch profile');
      }
    } catch (err) {
      setError('Failed to load profile');
      console.error('Profile fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Fetch user devices
  const fetchDevices = async () => {
    try {
      const response = await fetch('/api/account/devices');
      const result = await response.json();
      
      if (result.success) {
        setDevices(result.data.devices || []);
      }
    } catch (err) {
      console.error('Device fetch error:', err);
    }
  };

  // Fetch user sessions  
  const fetchSessions = async () => {
    try {
      const response = await fetch('/api/account/sessions');
      const result = await response.json();
      
      console.log('Sessions API response:', result);
      
      if (result.success) {
        console.log('Setting sessions:', result.data.sessions);
        setSessions(result.data.sessions || []);
      } else {
        console.error('Sessions API error:', result.error);
      }
    } catch (err) {
      console.error('Session fetch error:', err);
    }
  };

  // Fetch security logs
  const fetchSecurityLogs = async () => {
    try {
      const response = await fetch('/api/security/logs');
      const result = await response.json();
      
      if (result.success) {
        setSecurityLogs(result.data.logs || []);
      }
    } catch (err) {
      console.error('Security logs fetch error:', err);
    }
  };

  // Fetch passkeys
  const fetchPasskeys = async () => {
    try {
      const response = await fetch('/api/auth/passkeys');
      const result = await response.json();
      
      if (result.success) {
        setPasskeys(result.data.passkeys || []);
      }
    } catch (err) {
      console.error('Passkeys fetch error:', err);
    }
  };

  // Profile update function
  const handleUpdateProfile = async () => {
    setIsUpdatingProfile(true);
    try {
      const response = await fetch('/api/auth/profile', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(profileForm),
      });

      const result = await response.json();
      
      if (result.success) {
        // Update user state with the returned user data
        if (result.data && result.data.user) {
          setUser(result.data.user);
        } else {
          setUser(prev => ({ ...prev, ...profileForm }));
        }
        
        setEditingProfile(false);
        setError('');
        setSuccessMessage('');
        
        // Show email verification message if email was changed
        if (result.data && result.data.emailVerificationRequired) {
          setSuccessMessage(result.message || 'Profile updated successfully. Please check your new email address for a verification link.');
        } else {
          setSuccessMessage('Profile updated successfully!');
        }
        
        // Clear success message after 5 seconds
        setTimeout(() => setSuccessMessage(''), 5000);
      } else {
        setError(result.error || 'Failed to update profile');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsUpdatingProfile(false);
    }
  };

  // Resend email verification function
  const handleResendVerification = async () => {
    try {
      const response = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const result = await response.json();
      
      if (result.success) {
        setSuccessMessage('Verification email sent! Please check your inbox.');
        setError('');
        
        // Clear success message after 5 seconds
        setTimeout(() => setSuccessMessage(''), 5000);
      } else {
        setError(result.error || 'Failed to send verification email');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    }
  };

  // Password change function
  const handleChangePassword = async () => {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    setIsChangingPassword(true);
    try {
      const response = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          currentPassword: passwordForm.currentPassword,
          newPassword: passwordForm.newPassword,
        }),
      });

      const result = await response.json();
      
      if (result.success) {
        setPasswordForm({
          currentPassword: '',
          newPassword: '',
          confirmPassword: ''
        });
        setEditingPassword(false);
        setError('');
      } else {
        setError(result.error || 'Failed to change password');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsChangingPassword(false);
    }
  };

  // Remove device function
  const handleRemoveDevice = async (deviceId) => {
    setIsRemovingDevice(deviceId);
    try {
      const response = await fetch(`/api/devices/${deviceId}`, {
        method: 'DELETE',
      });

      const result = await response.json();
      
      if (result.success) {
        setDevices(prev => prev.filter(device => device.id !== deviceId));
      } else {
        setError(result.error || 'Failed to remove device');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsRemovingDevice(null);
    }
  };

  // Terminate session function
  const handleTerminateSession = async (sessionId) => {
    setIsTerminatingSession(sessionId);
    try {
      const response = await fetch(`/api/account/sessions`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ sessionId }),
      });

      const result = await response.json();
      
      if (result.success) {
        setSessions(prev => prev.filter(session => session.id !== sessionId));
      } else {
        setError(result.error || 'Failed to terminate session');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsTerminatingSession(null);
    }
  };

  // Delete passkey function
  const handleDeletePasskey = async (passkeyId) => {
    try {
      const response = await fetch('/api/auth/passkeys', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ action: 'delete', passkeyId }),
      });

      const result = await response.json();
      
      if (result.success) {
        setPasskeys(prev => prev.filter(passkey => passkey.id !== passkeyId));
      } else {
        setError(result.error || 'Failed to delete passkey');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    }
  };

  const handleLogout = async () => {
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
      });
      
      if (response.ok) {
        router.push('/auth/login');
      }
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error && !user) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-black mb-4">Error</h1>
          <p className="text-gray-600">{error}</p>
          <button
            onClick={() => router.push('/auth/login')}
            className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
          >
            Go to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                    <span className="text-white font-bold text-sm">IdP</span>
                  </div>
                  <span className="ml-3 text-xl font-semibold text-black">Identity Provider</span>
                </div>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center">
                <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center">
                  <span className="text-sm font-medium text-gray-700">
                    {user?.firstName?.[0]?.toUpperCase() || 'U'}
                  </span>
                </div>
                <span className="ml-2 text-sm font-medium text-gray-700">
                  {user?.firstName} {user?.lastName}
                </span>
              </div>
              <button
                onClick={handleLogout}
                className="text-gray-500 hover:text-gray-700 px-3 py-2 rounded-md text-sm font-medium"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-black">
            Welcome back, {user?.firstName}!
          </h1>
          <p className="mt-2 text-gray-600">
            Manage your account settings and security preferences
          </p>
        </div>

        {/* Email Verification Banner */}
        {user && !user.isVerified && (
          <div className="mb-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <svg className="w-5 h-5 text-blue-400" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3 flex-1">
                <h3 className="text-sm font-medium text-blue-800">
                  Email verification required
                </h3>
                <div className="mt-2 text-sm text-blue-700">
                  <p>
                    Please verify your email address ({user.email}) to ensure account security and enable all features.
                  </p>
                </div>
                <div className="mt-3">
                  <button
                    onClick={() => handleResendVerification()}
                    className="bg-blue-100 hover:bg-blue-200 text-blue-800 px-3 py-1 rounded-md text-sm font-medium transition-colors"
                  >
                    Resend verification email
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-md">
            {error}
            <button
              onClick={() => setError('')}
              className="ml-4 text-red-500 hover:text-red-700"
            >
              ×
            </button>
          </div>
        )}

        {/* Success Alert */}
        {successMessage && (
          <div className="mb-6 bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-md">
            {successMessage}
            <button
              onClick={() => setSuccessMessage('')}
              className="ml-4 text-green-500 hover:text-green-700"
            >
              ×
            </button>
          </div>
        )}

        {/* Profile Section */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold text-black">Profile Information</h2>
              {!editingProfile ? (
                <button
                  onClick={() => {
                    setEditingProfile(true);
                    setError('');
                    setSuccessMessage('');
                  }}
                  className="text-blue-600 hover:text-blue-800 font-medium"
                >
                  Edit
                </button>
              ) : (
                <div className="space-x-2">
                  <button
                    onClick={() => {
                      setEditingProfile(false);
                      setError('');
                      setSuccessMessage('');
                      setProfileForm({
                        firstName: user?.firstName || '',
                        lastName: user?.lastName || '',
                        email: user?.email || '',
                        username: user?.username || ''
                      });
                    }}
                    className="text-gray-600 hover:text-gray-800 font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleUpdateProfile}
                    disabled={isUpdatingProfile}
                    className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {isUpdatingProfile ? 'Saving...' : 'Save'}
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="p-6">
            {!editingProfile ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700">First Name</label>
                  <p className="mt-1 text-sm text-black">{user?.firstName || 'Not set'}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Last Name</label>
                  <p className="mt-1 text-sm text-black">{user?.lastName || 'Not set'}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Email</label>
                  <p className="mt-1 text-sm text-black">{user?.email}</p>
                  {user && !user.isVerified && (
                    <div className="mt-2 flex items-center">
                      <div className="flex items-center px-3 py-2 bg-amber-50 border border-amber-200 rounded-md">
                        <svg className="w-4 h-4 text-amber-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                        </svg>
                        <span className="text-sm text-amber-700">Email not verified</span>
                        <button
                          onClick={() => handleResendVerification()}
                          className="ml-3 text-sm text-amber-600 hover:text-amber-800 underline"
                        >
                          Resend verification
                        </button>
                      </div>
                    </div>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Username</label>
                  <p className="mt-1 text-sm text-black">{user?.username || 'Not set'}</p>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700">First Name</label>
                  <input
                    type="text"
                    value={profileForm.firstName}
                    onChange={(e) => setProfileForm(prev => ({ ...prev, firstName: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Last Name</label>
                  <input
                    type="text"
                    value={profileForm.lastName}
                    onChange={(e) => setProfileForm(prev => ({ ...prev, lastName: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Email</label>
                  <input
                    type="email"
                    value={profileForm.email}
                    onChange={(e) => setProfileForm(prev => ({ ...prev, email: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Username</label>
                  <input
                    type="text"
                    value={profileForm.username}
                    onChange={(e) => setProfileForm(prev => ({ ...prev, username: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Password Section */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="flex justify-between items-center">
              <h2 className="text-lg font-semibold text-black">Password</h2>
              {!editingPassword ? (
                <button
                  onClick={() => setEditingPassword(true)}
                  className="text-blue-600 hover:text-blue-800 font-medium"
                >
                  Change Password
                </button>
              ) : (
                <div className="space-x-2">
                  <button
                    onClick={() => {
                      setEditingPassword(false);
                      setPasswordForm({
                        currentPassword: '',
                        newPassword: '',
                        confirmPassword: ''
                      });
                    }}
                    className="text-gray-600 hover:text-gray-800 font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleChangePassword}
                    disabled={isChangingPassword}
                    className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {isChangingPassword ? 'Changing...' : 'Change Password'}
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="p-6">
            {!editingPassword ? (
              <p className="text-sm text-gray-600">
                Password was last changed on {user?.passwordLastChanged ? new Date(user.passwordLastChanged).toLocaleDateString() : 'unknown date'}
              </p>
            ) : (
              <div className="space-y-4 max-w-md">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Current Password</label>
                  <input
                    type="password"
                    value={passwordForm.currentPassword}
                    onChange={(e) => setPasswordForm(prev => ({ ...prev, currentPassword: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">New Password</label>
                  <input
                    type="password"
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm(prev => ({ ...prev, newPassword: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Confirm New Password</label>
                  <input
                    type="password"
                    value={passwordForm.confirmPassword}
                    onChange={(e) => setPasswordForm(prev => ({ ...prev, confirmPassword: e.target.value }))}
                    className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-black bg-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Active Sessions */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-black">Active Sessions</h2>
          </div>
          <div className="p-6">
            {sessions.length === 0 ? (
              <p className="text-gray-500">No active sessions found.</p>
            ) : (
              <div className="space-y-4">
                {sessions.map((session) => (
                  <div key={session.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                    <div>
                      <div className="flex items-center space-x-2">
                        <h3 className="font-medium text-black">{session.device || 'Unknown Device'}</h3>
                        {session.current && (
                          <span className="px-2 py-1 text-xs bg-green-100 text-green-800 rounded-full">Current</span>
                        )}
                      </div>
                      <p className="text-sm text-gray-500">
                        {session.location || 'Unknown location'} • {session.lastActive ? new Date(session.lastActive).toLocaleString() : 'Unknown time'}
                      </p>
                    </div>
                    {!session.current && (
                      <button
                        onClick={() => handleTerminateSession(session.id)}
                        disabled={isTerminatingSession === session.id}
                        className="text-red-600 hover:text-red-800 font-medium disabled:opacity-50"
                      >
                        {isTerminatingSession === session.id ? 'Terminating...' : 'Terminate'}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Trusted Devices */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-black">Trusted Devices</h2>
          </div>
          <div className="p-6">
            {devices.length === 0 ? (
              <p className="text-gray-500">No trusted devices found.</p>
            ) : (
              <div className="space-y-4">
                {devices.map((device) => (
                  <div key={device.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                    <div>
                      <h3 className="font-medium text-black">{device.name || 'Unknown Device'}</h3>
                      <p className="text-sm text-gray-500">
                        Last seen: {device.lastSeen ? new Date(device.lastSeen).toLocaleString() : 'Unknown'}
                      </p>
                    </div>
                    <button
                      onClick={() => handleRemoveDevice(device.id)}
                      disabled={isRemovingDevice === device.id}
                      className="text-red-600 hover:text-red-800 font-medium disabled:opacity-50"
                    >
                      {isRemovingDevice === device.id ? 'Removing...' : 'Remove'}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Passkeys */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-black">Passkeys</h2>
          </div>
          <div className="p-6">
            {!Array.isArray(passkeys) || passkeys.length === 0 ? (
              <p className="text-gray-500">No passkeys configured.</p>
            ) : (
              <div className="space-y-4">
                {passkeys.map((passkey) => (
                  <div key={passkey.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                    <div>
                      <h3 className="font-medium text-black">{passkey.name || 'Unnamed Passkey'}</h3>
                      <p className="text-sm text-gray-500">
                        Created: {passkey.createdAt ? new Date(passkey.createdAt).toLocaleDateString() : 'Unknown'} •
                        Last used: {passkey.lastUsed ? new Date(passkey.lastUsed).toLocaleDateString() : 'Never'}
                      </p>
                    </div>
                    <button
                      onClick={() => handleDeletePasskey(passkey.id)}
                      className="text-red-600 hover:text-red-800 font-medium"
                    >
                      Delete
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Security Activity */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-black">Recent Security Activity</h2>
          </div>
          <div className="p-6">
            {securityLogs.length === 0 ? (
              <p className="text-gray-500">No recent security activity.</p>
            ) : (
              <div className="space-y-4">
                {securityLogs.slice(0, 5).map((log, index) => (
                  <div key={index} className="flex items-start space-x-4">
                    <div className={`w-2 h-2 rounded-full mt-2 ${
                      log.event.includes('failed') || log.event.includes('blocked') 
                        ? 'bg-red-400' 
                        : 'bg-green-400'
                    }`}></div>
                    <div>
                      <p className="text-sm font-medium text-black">{log.event}</p>
                      <p className="text-sm text-gray-500">
                        {log.timestamp ? new Date(log.timestamp).toLocaleString() : 'Unknown time'} •
                        {log.ipAddress || 'Unknown IP'}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
