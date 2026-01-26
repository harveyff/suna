import { createClient } from '@/lib/supabase/server'
import { NextResponse } from 'next/server'

/**
 * Sync Session API Route
 * 
 * This route syncs the client-side session (localStorage) with server-side cookies
 * so that middleware can detect authenticated users.
 * 
 * Called after client-side token verification to ensure cookies are set.
 */
export async function POST() {
  try {
    const supabase = await createClient()
    
    // Get user to verify session exists
    const { data: { user }, error } = await supabase.auth.getUser()
    
    if (error || !user) {
      console.log('[Sync Session] No user found or error:', {
        hasError: !!error,
        errorMessage: error?.message,
        hasUser: !!user
      })
      return NextResponse.json({ 
        success: false, 
        message: 'No active session' 
      }, { status: 401 })
    }
    
    // Session exists - cookies should be set by createServerClient
    // Just return success to confirm session is synced
    console.log('[Sync Session] Session synced successfully:', {
      userId: user.id.substring(0, 8) + '...',
      email: user.email?.substring(0, 20) + '...'
    })
    
    return NextResponse.json({ 
      success: true, 
      user: {
        id: user.id,
        email: user.email
      }
    })
  } catch (error) {
    console.error('[Sync Session] Error syncing session:', error)
    return NextResponse.json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Unknown error' 
    }, { status: 500 })
  }
}

