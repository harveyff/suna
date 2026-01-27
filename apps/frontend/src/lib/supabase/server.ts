'use server'
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
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
          const allCookies = cookieStore.getAll();
          const authCookies = allCookies.filter(c => 
            c.name.includes('supabase') || 
            c.name.includes('auth') || 
            c.name === 'sb-supabase-kong-auth-token'
          );
          
          console.log('🍪 [Supabase Server] Getting cookies:', {
            totalCookies: allCookies.length,
            authCookiesCount: authCookies.length,
            authCookieNames: authCookies.map(c => c.name),
            timestamp: new Date().toISOString(),
          });
          
          return allCookies;
        },
        setAll(cookiesToSet) {
          // In Route Handlers, cookies().set() works correctly
          // We need to set cookies so they're available for the response
          console.log('🍪 [Supabase Server] Setting cookies:', {
            cookiesCount: cookiesToSet.length,
            cookieNames: cookiesToSet.map(c => c.name),
            timestamp: new Date().toISOString(),
          });
          
          cookiesToSet.forEach(({ name, value, options }) => {
            try {
              // Ensure cookies have proper options for cross-domain support
              const cookieOptions = {
                ...options,
                // Ensure path is set (default to /)
                path: options?.path || '/',
                // Ensure SameSite is set for cross-domain support
                sameSite: options?.sameSite || ('lax' as const),
                // Ensure httpOnly is set if specified
                httpOnly: options?.httpOnly ?? true,
                // Ensure secure is set based on environment
                secure: options?.secure ?? (process.env.NODE_ENV === 'production'),
              };
              
              cookieStore.set(name, value, cookieOptions);
              
              console.log('✅ [Supabase Server] Cookie set:', {
                name,
                valueLength: value?.length || 0,
                path: cookieOptions.path,
                sameSite: cookieOptions.sameSite,
                httpOnly: cookieOptions.httpOnly,
                secure: cookieOptions.secure,
                timestamp: new Date().toISOString(),
              });
            } catch (error) {
              // Log error but don't fail - cookies might already be set
              console.error(`❌ [Supabase Server] Failed to set cookie ${name}:`, {
                error: error instanceof Error ? error.message : String(error),
                cookieName: name,
                valueLength: value?.length || 0,
                options,
                timestamp: new Date().toISOString(),
              });
            }
          });
          
          console.log('🍪 [Supabase Server] Finished setting cookies:', {
            totalCookies: cookiesToSet.length,
            timestamp: new Date().toISOString(),
          });
        },
      },
    }
  )
}
