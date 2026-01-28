'use server'
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
  console.log('🔧 [Supabase Server Client] Creating client instance:', {
    timestamp: new Date().toISOString(),
    context: 'Server-side (Server Actions/Server Components)',
  });
  
  // Priority for server-side code:
  // 1. SUPABASE_URL (server-side env var, cluster-internal) - highest priority
  // 2. NEXT_PUBLIC_SUPABASE_URL (if not demo/placeholder) - fallback
  // 3. Cluster-internal default - last resort
  
  // Server-side environment variables (set via Kubernetes ConfigMap)
  // These are cluster-internal URLs and should be used for server-side rendering
  let supabaseUrl = (process.env.SUPABASE_URL || '').trim()
  let supabaseKey = (process.env.SUPABASE_ANON_KEY || '').trim()

  // If server-side env vars are not set, fall back to NEXT_PUBLIC_* vars
  // But check if they are demo/placeholder values first
  if (!supabaseUrl || supabaseUrl.trim() === '') {
    const publicUrl = (process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim()
    
    // Check if public URL is a relative path (e.g., /supabase)
    if (publicUrl && publicUrl.startsWith('/')) {
      // Relative paths can't be used server-side, use cluster-internal default
      supabaseUrl = 'http://supabase-kong:8000'
    } else if (publicUrl && 
                !publicUrl.includes('demo.supabase.co') && 
                !publicUrl.includes('placeholder')) {
      // Use public URL if it's not a demo/placeholder value
      supabaseUrl = publicUrl
    } else {
      // Use cluster-internal default
      supabaseUrl = 'http://supabase-kong:8000'
    }
  }

  // Check if URL is still demo/placeholder and replace with cluster-internal default
  if (supabaseUrl.includes('demo.supabase.co') || 
      supabaseUrl.includes('placeholder') ||
      supabaseUrl.trim() === '') {
    console.warn('[Supabase Server] Detected demo/placeholder URL, using cluster-internal default')
    supabaseUrl = 'http://supabase-kong:8000'
  }

  // Handle key: use server-side env var first, then fall back to NEXT_PUBLIC_*
  if (!supabaseKey || supabaseKey.trim() === '') {
    const publicKey = (process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '').trim()
    if (publicKey && publicKey.trim() !== '') {
      supabaseKey = publicKey
    } else {
      // Last resort: use demo key (should not happen in production)
      console.warn('[Supabase Server] Using demo key - runtime env vars may not be set correctly')
      supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0'
    }
  }

  const cookieStore = await cookies()

  return createServerClient(
    supabaseUrl,
    supabaseKey,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll()
        },
        setAll(cookiesToSet) {
          try {
            console.log('🍪 [Supabase Server] Setting cookies:', {
              cookieCount: cookiesToSet.length,
              cookieNames: cookiesToSet.map(c => c.name),
              timestamp: new Date().toISOString(),
            });
            cookiesToSet.forEach(({ name, value, options }) => {
              cookieStore.set(name, value, options);
              console.log('🍪 [Supabase Server] Cookie set:', {
                name,
                hasValue: !!value,
                valueLength: value?.length || 0,
                options: options ? {
                  path: options.path,
                  maxAge: options.maxAge,
                  sameSite: options.sameSite,
                  secure: options.secure,
                  httpOnly: options.httpOnly,
                } : undefined,
                timestamp: new Date().toISOString(),
              });
            });
          } catch (error) {
            // The `setAll` method was called from a Server Component.
            // This can be ignored if you have middleware refreshing
            // user sessions.
            console.error('❌ [Supabase Server] Error setting cookies:', {
              error: error instanceof Error ? error.message : String(error),
              cookieCount: cookiesToSet.length,
              timestamp: new Date().toISOString(),
            });
          }
        },
      },
    }
  )
}
