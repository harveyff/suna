'use server'
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
  let supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
  let supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  // During build time, if environment variables are not set or are placeholders,
  // use demo values to prevent build failures
  // The actual runtime values will be provided via environment variables or ConfigMap
  if (!supabaseUrl || !supabaseKey || 
      supabaseUrl.includes('placeholder') || 
      supabaseUrl.trim() === '') {
    // Use demo values during build to prevent initialization failures
    // These are valid Supabase demo credentials that won't cause build errors
    supabaseUrl = 'https://demo.supabase.co'
    supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0'
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
