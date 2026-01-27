import { createBrowserClient } from '@supabase/ssr'

// Cache for Supabase client to avoid recreating it
let supabaseClient: ReturnType<typeof createBrowserClient> | null = null
let lastConfigHash: string | null = null

/**
 * Get Supabase configuration with multiple fallback strategies
 * Priority: 1) window.__SUPABASE_CONFIG__ (runtime injection), 2) data attributes, 3) process.env (build-time)
 */
function getSupabaseConfig(): { url: string; anonKey: string } {
  let supabaseUrl = ''
  let supabaseKey = ''
  
  // Strategy 1: Get from window.__SUPABASE_CONFIG__ (runtime injection from server)
  if (typeof window !== 'undefined') {
    const windowConfig = (window as any).__SUPABASE_CONFIG__
    if (windowConfig && typeof windowConfig === 'object') {
      if (windowConfig.url && typeof windowConfig.url === 'string') {
        supabaseUrl = windowConfig.url.trim()
      }
      if (windowConfig.anonKey && typeof windowConfig.anonKey === 'string') {
        supabaseKey = windowConfig.anonKey.trim()
      }
    }
  }
  
  // Strategy 2: Get from data attributes (fallback if window config not ready)
  if ((!supabaseUrl || !supabaseKey) && typeof document !== 'undefined') {
    const urlAttr = document.documentElement.getAttribute('data-supabase-url')
    const keyAttr = document.documentElement.getAttribute('data-supabase-key')
    if (urlAttr) supabaseUrl = urlAttr.trim()
    if (keyAttr) supabaseKey = keyAttr.trim()
  }
  
  // Strategy 3: Fallback to process.env (build-time values)
  if (!supabaseUrl) {
    supabaseUrl = (process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim()
  }
  if (!supabaseKey) {
    supabaseKey = (process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '').trim()
  }
  
  // Normalize URL: handle relative paths
  if (supabaseUrl && supabaseUrl.startsWith('/')) {
    if (typeof window !== 'undefined' && window.location) {
      supabaseUrl = window.location.origin + supabaseUrl
    } else {
      supabaseUrl = 'https://placeholder.supabase.co'
    }
  }
  
  // Final fallback: use current origin + /supabase if URL is invalid
  if (!supabaseUrl || supabaseUrl.includes('placeholder') || supabaseUrl.trim() === '') {
    if (typeof window !== 'undefined' && window.location) {
      supabaseUrl = window.location.origin + '/supabase'
    } else {
      supabaseUrl = 'https://demo.supabase.co'
    }
  }
  
  // Final fallback: use demo key if key is invalid
  if (!supabaseKey || supabaseKey.trim() === '') {
    supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0'
    if (typeof window !== 'undefined' && typeof console !== 'undefined') {
      console.warn('[Supabase Client] NEXT_PUBLIC_SUPABASE_ANON_KEY is not set, using demo key. Supabase features may not work correctly.')
    }
  }
  
  return { url: supabaseUrl, anonKey: supabaseKey }
}

export function createClient() {
  // Get configuration with multiple fallback strategies
  const config = getSupabaseConfig()
  
  // Create a hash of the config to detect changes
  const configHash = `${config.url}|${config.anonKey}`
  
  // Recreate client if config changed or client doesn't exist
  if (!supabaseClient || lastConfigHash !== configHash) {
    try {
      console.log('🔧 [Supabase Client] Creating client:', {
        url: config.url,
        anonKeyPrefix: config.anonKey.substring(0, 20) + '...',
        anonKeyLength: config.anonKey.length,
        timestamp: new Date().toISOString(),
      });
      
      supabaseClient = createBrowserClient(config.url, config.anonKey)
      lastConfigHash = configHash
      
      console.log('✅ [Supabase Client] Client created successfully:', {
        url: config.url,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('❌ [Supabase Client] Failed to create client:', {
        error: error instanceof Error ? error.message : String(error),
        url: config.url,
        timestamp: new Date().toISOString(),
      });
      // Return a client with fallback config even on error
      supabaseClient = createBrowserClient(
        config.url,
        config.anonKey
      )
    }
  }
  
  return supabaseClient
}
