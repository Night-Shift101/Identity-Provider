/**
 * Passkeys Management API Route
 * Handles passkey CRUD operations
 * @author IdP System
 */

import { NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/lib/auth-helpers';
import { prisma } from '@/lib/database';
import { logSecurityEvent } from '@/lib/security';

export async function GET(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const userId = authResult.data.user.id;

    // Get user's passkeys
    const passkeys = await prisma.webAuthnCredential.findMany({
      where: { userId },
      select: {
        id: true,
        credentialId: true,
        name: true,
        createdAt: true,
        lastUsed: true
      },
      orderBy: { createdAt: 'desc' }
    });

    return NextResponse.json({
      success: true,
      data: { passkeys }
    });

  } catch (error) {
    console.error('Passkeys fetch error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

export async function DELETE(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const { passkeyId } = await request.json();

    if (!passkeyId) {
      return NextResponse.json({
        success: false,
        error: 'Passkey ID is required'
      }, { status: 400 });
    }

    const userId = authResult.data.user.id;

    // Delete the passkey
    const deletedPasskey = await prisma.webAuthnCredential.delete({
      where: {
        id: passkeyId,
        userId: userId
      }
    });

    // Log security event
    await logSecurityEvent(userId, 'passkey_deleted', {
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
      credentialId: deletedPasskey.credentialId,
      credentialName: deletedPasskey.name
    });

    return NextResponse.json({
      success: true,
      data: { message: 'Passkey deleted successfully' }
    });

  } catch (error) {
    if (error.code === 'P2025') {
      return NextResponse.json({
        success: false,
        error: 'Passkey not found'
      }, { status: 404 });
    }

    console.error('Delete passkey error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

export async function POST(request) {
  try {
    // Get authenticated user
    const authResult = await getAuthenticatedUser(request);
    if (!authResult.success) {
      return NextResponse.json({
        success: false,
        error: authResult.error || 'Authentication required'
      }, { status: 401 });
    }

    const { action, passkeyId, name } = await request.json();

    switch (action) {
      case 'rename':
        return await handleRenamePasskey(passkeyId, name, authResult.data.user.id, request);
      
      case 'delete':
        return await handleDeletePasskey(passkeyId, authResult.data.user.id, request);
      
      default:
        return NextResponse.json({
          success: false,
          error: 'Invalid action'
        }, { status: 400 });
    }

  } catch (error) {
    console.error('Passkey management error:', error);
    return NextResponse.json({
      success: false,
      error: 'Internal server error'
    }, { status: 500 });
  }
}

async function handleRenamePasskey(passkeyId, name, userId, request) {
  try {
    if (!passkeyId || !name || name.trim().length === 0) {
      return NextResponse.json({
        success: false,
        error: 'Passkey ID and name are required'
      }, { status: 400 });
    }

    if (name.length > 50) {
      return NextResponse.json({
        success: false,
        error: 'Name must be 50 characters or less'
      }, { status: 400 });
    }

    // Update passkey name
    const updatedPasskey = await prisma.webAuthnCredential.updateMany({
      where: {
        id: passkeyId,
        userId
      },
      data: {
        name: name.trim()
      }
    });

    if (updatedPasskey.count === 0) {
      return NextResponse.json({
        success: false,
        error: 'Passkey not found'
      }, { status: 404 });
    }

    // Log security event
    await logSecurityEvent({
      userId,
      event: 'passkey_renamed',
      details: {
        passkeyId,
        newName: name.trim()
      },
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || ''
    });

    return NextResponse.json({
      success: true,
      message: 'Passkey renamed successfully'
    });

  } catch (error) {
    console.error('Rename passkey error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to rename passkey'
    }, { status: 500 });
  }
}

async function handleDeletePasskey(passkeyId, userId, request) {
  try {
    if (!passkeyId) {
      return NextResponse.json({
        success: false,
        error: 'Passkey ID is required'
      }, { status: 400 });
    }

    // Check if this is the user's last passkey
    const userPasskeys = await prisma.webAuthnCredential.count({
      where: { userId }
    });

    // Get user to check if they have a password as backup
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { password: true }
    });

    // Prevent deletion if it's the only authentication method
    if (userPasskeys === 1 && !user?.password) {
      return NextResponse.json({
        success: false,
        error: 'Cannot delete your last passkey without a password set. Please set a password first.'
      }, { status: 400 });
    }

    // Delete passkey
    const deletedPasskey = await prisma.webAuthnCredential.deleteMany({
      where: {
        id: passkeyId,
        userId
      }
    });

    if (deletedPasskey.count === 0) {
      return NextResponse.json({
        success: false,
        error: 'Passkey not found'
      }, { status: 404 });
    }

    // Log security event
    await logSecurityEvent({
      userId,
      event: 'passkey_deleted',
      details: {
        passkeyId,
        remainingPasskeys: userPasskeys - 1
      },
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || ''
    });

    return NextResponse.json({
      success: true,
      message: 'Passkey deleted successfully'
    });

  } catch (error) {
    console.error('Delete passkey error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to delete passkey'
    }, { status: 500 });
  }
}
