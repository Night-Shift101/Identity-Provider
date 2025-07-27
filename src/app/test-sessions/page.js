/**
 * Test Sessions Display Page
 * For debugging session UI rendering
 */

'use client';

import { useState, useEffect } from 'react';

export default function TestSessionsPage() {
  const [sessions, setSessions] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchSessions();
  }, []);

  const fetchSessions = async () => {
    try {
      // TODO: SECURITY - Remove or protect debug endpoints in production
      // TODO: LOGGING - Use proper logging framework instead of console.log
      console.log('Fetching test sessions...');
      const response = await fetch('/api/test-sessions');
      const result = await response.json();
      
      console.log('Sessions API response:', result);
      
      if (result.success) {
        console.log('Setting sessions:', result.data.sessions);
        setSessions(result.data.sessions);
      } else {
        console.error('Sessions API error:', result.error);
        setError('Failed to load sessions: ' + result.error);
      }
    } catch (err) {
      console.error('Session fetch error:', err);
      setError('Network error');
    }
  };

  const terminateSession = (sessionId) => {
    // TODO: FUNCTIONALITY - Implement session termination
    // TODO: LOGGING - Use proper logging framework instead of console.log
    console.log('Terminate session:', sessionId);
  };  if (isLoading) {
    return <div className="p-8">Loading...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-6">
        <h1 className="text-2xl font-bold text-black mb-8">Test Sessions Display</h1>
        
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
                        className="text-red-600 hover:text-red-800 font-medium"
                      >
                        Terminate
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="text-sm text-gray-500 mt-4">
          <p>Sessions count: {sessions.length}</p>
          <p>Check browser console for debug logs</p>
        </div>
      </div>
    </div>
  );
}
