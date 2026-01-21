'use server'
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  // Check if we're in build mode or using placeholder values
  // During build, Next.js may try to statically generate pages which would fail
  // if Supabase client initialization requires valid credentials
  const isBuildTime = process.env.NODE_ENV === 'production' && !process.env.VERCEL && !process.env.NEXT_RUNTIME
  const isPlaceholder = !supabaseUrl || !supabaseKey || 
      supabaseUrl.includes('placeholder') || 
      supabaseUrl.includes('demo.supabase.co')

  // If in build mode with placeholder values, use demo values to allow build to complete
  // The actual runtime values will be provided via environment variables or ConfigMap
  if (isBuildTime && isPlaceholder) {
    // Use demo values during build to prevent initialization failures
    // These are valid Supabase demo credentials that won't cause build errors
    const cookieStore = await cookies()
    return createServerClient(
      'https://demo.supabase.co',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0',
      {
        cookies: {
          getAll() {
            return cookieStore.getAll()
          },
          setAll(cookiesToSet) {
            try {
              cookiesToSet.forEach(({ name, value, options }) =>
                cookieStore.set(name, value, options)
              )
            } catch {
              // The `setAll` method was called from a Server Component.
              // This can be ignored if you have middleware refreshing
              // user sessions.
            }
          },
        },
      }
    )
  }

  // Normal initialization with actual values
  if (!supabaseUrl || !supabaseKey) {
    throw new Error('Supabase configuration not available. Please configure NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY.')
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
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            )
          } catch {
            // The `setAll` method was called from a Server Component.
            // This can be ignored if you have middleware refreshing
            // user sessions.
          }
        },
      },
    }
  )
}
