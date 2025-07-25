/**
 * Email Test API Route
 * Test SMTP configuration
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { sendEmailVerification } from '@/lib/email';

export async function POST(request) {
  try {
    const { email } = await request.json();
    
    if (!email) {
      return NextResponse.json(
        { error: 'Email is required' },
        { status: 400 }
      );
    }

    console.log('Testing email sending to:', email);
    console.log('SMTP Config:', {
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      user: process.env.SMTP_USER,
      from: process.env.EMAIL_FROM,
      passLength: process.env.SMTP_PASS?.length
    });

    const result = await sendEmailVerification(email, 'test-token-123', 'Test');
    
    console.log('Email result:', result);
    
    return NextResponse.json({
      success: result.success,
      error: result.error,
      data: result.data
    });

  } catch (error) {
    console.error('Email test error:', error);
    return NextResponse.json(
      { error: 'Internal server error', details: error.message },
      { status: 500 }
    );
  }
}
