/**
 * Test Session API - No Auth Required
 * For debugging session display issues
 */

import { NextResponse } from 'next/server';

export async function GET(request) {
  console.log('\n=== TEST SESSIONS API CALLED ===');
  
  const testSessions = [
    {
      id: 'test-session-1',
      ipAddress: '127.0.0.1',
      device: 'Mac - Chrome',
      current: true,
      expires: new Date(),
      lastActive: new Date(),
      location: 'Local'
    },
    {
      id: 'test-session-2', 
      ipAddress: '192.168.1.100',
      device: 'Windows - Firefox',
      current: false,
      expires: new Date(),
      lastActive: new Date(Date.now() - 3600000), // 1 hour ago
      location: 'Office Network'
    }
  ];

  console.log('Returning test sessions:', JSON.stringify(testSessions, null, 2));
  console.log('=== END TEST SESSIONS API ===\n');

  return NextResponse.json({
    success: true,
    data: {
      sessions: testSessions,
      currentSessionId: 'test-session-1'
    }
  });
}
