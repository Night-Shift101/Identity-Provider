/**
 * Dashboard Page Component
 * Main dashboard after successful authentication with inline editing
 * @author IdP System
 */

'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import TrustedDevices from '@/components/TrustedDevices';

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
  const [mfaSetup, setMfaSetup] = useState(null);
  const [backupCodes, setBackupCodes] = useState([]);
  
  // MFA states
  const [showMfaSetup, setShowMfaSetup] = useState(false);
  const [showBackupCodes, setShowBackupCodes] = useState(false);
  const [mfaVerificationCode, setMfaVerificationCode] = useState('');
  const [isEnablingMfa, setIsEnablingMfa] = useState(false);
  const [isDisablingMfa, setIsDisablingMfa] = useState(false);
  
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
      const response = await fetch('/api/auth/profile', {
        credentials: 'include'
      });
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
      // TODO: LOGGING - Use proper logging framework instead of console.error
      // TODO: ERROR_HANDLING - Add user-friendly error messages
      // TODO: UX - Show loading states and better error UI
      console.error('Profile fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Fetch user devices
  const fetchDevices = async () => {
    try {
      const response = await fetch('/api/account/devices', {
        credentials: 'include'
      });
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
      const response = await fetch('/api/account/sessions', {
        credentials: 'include'
      });
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
      const response = await fetch('/api/security/logs', {
        credentials: 'include'
      });
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
      const response = await fetch('/api/auth/passkeys', {
        credentials: 'include'
      });
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
        credentials: 'include',
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
        // TODO: UX - Replace setTimeout with proper toast notification system
        // TODO: ACCESSIBILITY - Announce success to screen readers
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
        credentials: 'include',
      });

      const result = await response.json();
      
      if (result.success) {
        setSuccessMessage('Verification email sent! Please check your inbox.');
        setError('');
        
        // Clear success message after 5 seconds
        // TODO: UX - Replace setTimeout with proper toast notification system
        // TODO: ACCESSIBILITY - Announce success to screen readers
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
        credentials: 'include',
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
        credentials: 'include',
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
        credentials: 'include',
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
        credentials: 'include',
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
        credentials: 'include',
      });
      
      if (response.ok) {
        router.push('/auth/login');
      }
    } catch (err) {
      console.error('Logout error:', err);
    }
  };

  // MFA Setup Functions
  const handleStartMfaSetup = async () => {
    setIsEnablingMfa(true);
    try {
      const response = await fetch('/api/auth/mfa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'initialize'
        }),
      });

      const result = await response.json();
      
      if (result.success) {
        setMfaSetup(result.data);
        setShowMfaSetup(true);
        setError('');
      } else {
        setError(result.error || 'Failed to start MFA setup');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsEnablingMfa(false);
    }
  };

  const handleEnableMfa = async () => {
    if (!mfaVerificationCode || mfaVerificationCode.length !== 6) {
      setError('Please enter a valid 6-digit verification code');
      return;
    }

    setIsEnablingMfa(true);
    try {
      const response = await fetch('/api/auth/mfa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'verify',
          secret: mfaSetup.secret,
          token: mfaVerificationCode
        }),
      });

      const result = await response.json();
      
      if (result.success) {
        setUser(prev => ({ ...prev, mfaEnabled: true }));
        setBackupCodes(result.data.backupCodes || []);
        setShowMfaSetup(false);
        setShowBackupCodes(true);
        setMfaVerificationCode('');
        setError('');
        setSuccessMessage('MFA enabled successfully! Please save your backup codes.');
        setTimeout(() => setSuccessMessage(''), 5000);
      } else {
        setError(result.error || 'Failed to enable MFA');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsEnablingMfa(false);
    }
  };

  const handleDisableMfa = async () => {
    if (!window.confirm('Are you sure you want to disable MFA? This will make your account less secure.')) {
      return;
    }

    setIsDisablingMfa(true);
    try {
      const response = await fetch('/api/auth/mfa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'disable'
        }),
      });

      const result = await response.json();
      
      if (result.success) {
        setUser(prev => ({ ...prev, mfaEnabled: false }));
        setBackupCodes([]);
        setError('');
        setSuccessMessage('MFA disabled successfully.');
        setTimeout(() => setSuccessMessage(''), 5000);
      } else {
        setError(result.error || 'Failed to disable MFA');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setIsDisablingMfa(false);
    }
  };

  const handleRegenerateBackupCodes = async () => {
    if (!window.confirm('Are you sure you want to regenerate backup codes? Your old codes will no longer work.')) {
      return;
    }

    try {
      const response = await fetch('/api/auth/mfa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          action: 'regenerate-backup-codes'
        }),
      });

      const result = await response.json();
      
      if (result.success) {
        setBackupCodes(result.data.backupCodes || []);
        setShowBackupCodes(true);
        setError('');
        setSuccessMessage('New backup codes generated successfully.');
        setTimeout(() => setSuccessMessage(''), 5000);
      } else {
        setError(result.error || 'Failed to regenerate backup codes');
      }
    } catch (err) {
      setError('Network error. Please try again.');
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

        {/* Trusted Devices & Active Sessions */}
        <TrustedDevices />

        {/* Multi-Factor Authentication */}
        <div className="bg-white rounded-lg shadow mb-8">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-semibold text-black">Multi-Factor Authentication</h2>
            <p className="text-sm text-gray-600 mt-1">Add an extra layer of security to your account</p>
          </div>
          <div className="p-6">
            {user?.mfaEnabled ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-green-50 border border-green-200 rounded-lg">
                  <div className="flex items-center">
                    <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                    <div>
                      <h3 className="font-medium text-green-800">MFA Enabled</h3>
                      <p className="text-sm text-green-600">Your account is protected with multi-factor authentication</p>
                    </div>
                  </div>
                  <button
                    onClick={handleDisableMfa}
                    disabled={isDisablingMfa}
                    className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 disabled:opacity-50"
                  >
                    {isDisablingMfa ? 'Disabling...' : 'Disable MFA'}
                  </button>
                </div>
                
                <div className="border-t pt-4">
                  <h4 className="font-medium text-gray-900 mb-2">Backup Codes</h4>
                  <p className="text-sm text-gray-600 mb-3">
                    Use these codes to access your account if you lose your authenticator device
                  </p>
                  <div className="space-x-3">
                    <button
                      onClick={() => setShowBackupCodes(true)}
                      className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
                    >
                      View Codes
                    </button>
                    <button
                      onClick={handleRegenerateBackupCodes}
                      className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700"
                    >
                      Regenerate Codes
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <div className="flex items-center">
                    <div className="w-2 h-2 bg-yellow-500 rounded-full mr-3"></div>
                    <div>
                      <h3 className="font-medium text-yellow-800">MFA Disabled</h3>
                      <p className="text-sm text-yellow-600">Enable MFA for enhanced account security</p>
                    </div>
                  </div>
                  <button
                    onClick={handleStartMfaSetup}
                    disabled={isEnablingMfa}
                    className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50"
                  >
                    {isEnablingMfa ? 'Starting...' : 'Enable MFA'}
                  </button>
                </div>
                
                <div className="border-t pt-4">
                  <h4 className="font-medium text-gray-900 mb-2">What is MFA?</h4>
                  <p className="text-sm text-gray-600">
                    Multi-Factor Authentication adds an extra layer of security by requiring a second form of 
                    verification in addition to your password. Use an authenticator app like Google Authenticator 
                    or Authy to generate time-based codes.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* MFA Setup Modal */}
        {showMfaSetup && mfaSetup && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Enable Multi-Factor Authentication</h3>
              
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600 mb-3">
                    1. Install an authenticator app like Google Authenticator or Authy
                  </p>
                  <p className="text-sm text-gray-600 mb-3">
                    2. Scan this QR code with your authenticator app:
                  </p>
                  <div className="flex justify-center p-4 bg-gray-50 rounded-lg">
                    <img 
                      src={mfaSetup.qrCode} 
                      alt="MFA QR Code" 
                      className="w-48 h-48"
                    />
                  </div>
                  <p className="text-sm text-gray-600 mt-3">
                    Or manually enter this secret: <code className="bg-gray-100 px-2 py-1 rounded text-xs">{mfaSetup.secret}</code>
                  </p>
                </div>
                
                <div>
                  <label htmlFor="mfaCode" className="block text-sm font-medium text-gray-700 mb-2">
                    3. Enter the 6-digit code from your authenticator app:
                  </label>
                  <input
                    id="mfaCode"
                    type="text"
                    value={mfaVerificationCode}
                    onChange={(e) => setMfaVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="000000"
                    maxLength="6"
                  />
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => {
                    setShowMfaSetup(false);
                    setMfaVerificationCode('');
                    setMfaSetup(null);
                  }}
                  className="px-4 py-2 text-gray-700 bg-gray-200 rounded-md hover:bg-gray-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleEnableMfa}
                  disabled={isEnablingMfa || mfaVerificationCode.length !== 6}
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
                >
                  {isEnablingMfa ? 'Enabling...' : 'Enable MFA'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Backup Codes Modal */}
        {showBackupCodes && backupCodes.length > 0 && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">MFA Backup Codes</h3>
              
              <div className="space-y-4">
                <p className="text-sm text-gray-600">
                  Save these backup codes in a safe place. Each code can only be used once.
                </p>
                
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                    {backupCodes.map((code, index) => (
                      <div key={index} className="text-center py-1">
                        {code}
                      </div>
                    ))}
                  </div>
                </div>
                
                <div className="bg-yellow-50 border border-yellow-200 p-3 rounded-lg">
                  <p className="text-sm text-yellow-800">
                    <strong>Important:</strong> Store these codes securely. If you lose access to your 
                    authenticator device, these codes are the only way to regain access to your account.
                  </p>
                </div>
              </div>
              
              <div className="flex justify-end space-x-3 mt-6">
                <button
                  onClick={() => {
                    const codesText = backupCodes.join('\n');
                    navigator.clipboard.writeText(codesText);
                  }}
                  className="px-4 py-2 text-blue-600 bg-blue-100 rounded-md hover:bg-blue-200"
                >
                  Copy Codes
                </button>
                <button
                  onClick={() => setShowBackupCodes(false)}
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        )}

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
            {/* TODO: FUNCTIONALITY - Add pagination and search functionality for security logs */}
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
