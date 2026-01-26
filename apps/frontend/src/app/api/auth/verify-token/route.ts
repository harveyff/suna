import { createServerClient } from '@supabase/ssr'
import { NextRequest, NextResponse } from 'next/server'
import { cookies } from 'next/headers'

/**
 * Verify Token API Route
 * 
 * This route verifies magic link tokens server-side and sets cookies
 * so that middleware can detect authenticated users.
 * 
 * CRITICAL: We need to manually handle cookies in API routes to ensure
 * they are properly set in the response.
 */
export async function POST(request: NextRequest) {
  const startTime = Date.now()
  let response: NextResponse
  
  try {
    console.log('[Verify Token API] 📥 Request received:', {
      method: request.method,
      url: request.url,
      hasBody: true,
      timestamp: new Date().toISOString()
    })
    
    // Check incoming cookies
    const incomingCookies = request.cookies.getAll()
    console.log('[Verify Token API] 🍪 Incoming cookies:', {
      count: incomingCookies.length,
      cookieNames: incomingCookies.map(c => c.name),
      hasAuthCookies: incomingCookies.some(c => c.name.includes('auth') || c.name.includes('supabase'))
    })
    
    const body = await request.json()
    const { token_hash, type } = body
    
    console.log('[Verify Token API] 📋 Request body parsed:', {
      hasTokenHash: !!token_hash,
      tokenHashPrefix: token_hash ? token_hash.substring(0, 20) + '...' : 'missing',
      type,
      bodyKeys: Object.keys(body)
    })
    
    if (!token_hash || !type) {
      console.error('[Verify Token API] ❌ Missing required fields:', {
        hasTokenHash: !!token_hash,
        hasType: !!type
      })
      return NextResponse.json({ 
        success: false, 
        message: 'Missing token_hash or type' 
      }, { status: 400 })
    }
    
    // Get Supabase URL and key (same logic as server.ts)
    let supabaseUrl = (process.env.SUPABASE_URL || '').trim()
    let supabaseKey = (process.env.SUPABASE_ANON_KEY || '').trim()
    
    if (!supabaseUrl || supabaseUrl.trim() === '') {
      const publicUrl = (process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim()
      if (publicUrl && publicUrl.startsWith('/')) {
        supabaseUrl = 'http://supabase-kong:8000'
      } else if (publicUrl && !publicUrl.includes('demo.supabase.co') && !publicUrl.includes('placeholder')) {
        supabaseUrl = publicUrl
      } else {
        supabaseUrl = 'http://supabase-kong:8000'
      }
    }
    
    if (supabaseUrl.includes('demo.supabase.co') || supabaseUrl.includes('placeholder') || supabaseUrl.trim() === '') {
      supabaseUrl = 'http://supabase-kong:8000'
    }
    
    if (!supabaseKey || supabaseKey.trim() === '') {
      const publicKey = (process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '').trim()
      if (publicKey && publicKey.trim() !== '') {
        supabaseKey = publicKey
      } else {
        supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0'
      }
    }
    
    console.log('[Verify Token API] 🔧 Creating Supabase server client with manual cookie handling...')
    
    // Create response first so we can set cookies on it
    response = NextResponse.json({ success: false, message: 'Processing...' })
    
    // Track cookies that need to be set
    const cookiesToSet: Array<{ name: string; value: string; options?: any }> = []
    
    // Create Supabase client with manual cookie handling for API routes
    const supabase = createServerClient(
      supabaseUrl,
      supabaseKey,
      {
        cookies: {
          getAll() {
            return request.cookies.getAll()
          },
          setAll(cookiesToSetArray) {
            console.log('[Verify Token API] 🍪 setAll() called with cookies:', {
              count: cookiesToSetArray.length,
              cookies: cookiesToSetArray.map(({ name, value, options }) => ({
                name,
                valueLength: value?.length || 0,
                valuePrefix: value?.substring(0, 30) + '...' || 'empty',
                hasOptions: !!options,
                options: options ? {
                  httpOnly: options.httpOnly,
                  secure: options.secure,
                  sameSite: options.sameSite,
                  path: options.path,
                  maxAge: options.maxAge,
                  expires: options.expires ? new Date(options.expires).toISOString() : undefined,
                  domain: options.domain
                } : null
              }))
            })
            
            // Store cookies to be set in response
            cookiesToSetArray.forEach(({ name, value, options }, index) => {
              cookiesToSet.push({ name, value, options })
              
              const cookieOptions = {
                ...options,
                httpOnly: options?.httpOnly ?? true,
                secure: options?.secure ?? true,
                sameSite: options?.sameSite ?? 'lax',
                path: options?.path ?? '/',
              }
              
              // Also set in response
              response.cookies.set(name, value, cookieOptions)
              
              console.log(`[Verify Token API] 🍪 Cookie ${index + 1}/${cookiesToSetArray.length} added to queue and response:`, {
                name,
                valueLength: value?.length || 0,
                valuePrefix: value?.substring(0, 30) + '...',
                finalOptions: cookieOptions
              })
            })
            
            console.log('[Verify Token API] 🍪 All cookies queued for response:', {
              totalCount: cookiesToSet.length,
              cookieNames: cookiesToSet.map(c => c.name),
              note: 'These cookies will be included in the final response'
            })
          },
        },
      }
    )
    
    // Check cookies before verification
    const cookiesBefore = request.cookies.getAll()
    console.log('[Verify Token API] 🍪 Cookies before verification:', {
      count: cookiesBefore.length,
      cookieNames: cookiesBefore.map(c => c.name)
    })
    
    console.log('[Verify Token API] 🔐 Calling verifyOtp...')
    const verifyStartTime = Date.now()
    
    // Verify token server-side - this will trigger setAll and queue cookies
    const { data, error } = await supabase.auth.verifyOtp({
      token_hash,
      type: type as 'magiclink',
    })
    
    const verifyDuration = Date.now() - verifyStartTime
    console.log('[Verify Token API] ⏱️ verifyOtp completed:', {
      duration: `${verifyDuration}ms`,
      hasData: !!data,
      hasError: !!error,
      hasUser: !!data?.user,
      cookiesQueued: cookiesToSet.length,
      errorMessage: error?.message,
      errorStatus: error?.status,
      errorCode: error?.code
    })
    
    if (error) {
      console.error('[Verify Token API] ❌ Verification failed:', {
        error: error.message,
        status: error.status,
        code: error.code,
        name: error.name,
        verifyDuration: `${verifyDuration}ms`
      })
      
      return NextResponse.json({ 
        success: false, 
        error: error.message,
        code: error.code,
        status: error.status
      }, { status: error.status || 400 })
    }
    
    if (!data.user) {
      console.error('[Verify Token API] ❌ No user returned from verification:', {
        hasData: !!data,
        dataKeys: data ? Object.keys(data) : [],
        verifyDuration: `${verifyDuration}ms`
      })
      return NextResponse.json({ 
        success: false, 
        message: 'No user returned from verification' 
      }, { status: 400 })
    }
    
    console.log('[Verify Token API] ✅ Token verified, user returned:', {
      userId: data.user.id?.substring(0, 8) + '...',
      email: data.user.email?.substring(0, 20) + '...',
      hasSession: !!data.session,
      sessionTokenPrefix: data.session?.access_token?.substring(0, 20) + '...' || 'none',
      cookiesQueued: cookiesToSet.length
    })
    
    // Session is now set in cookies via createServerClient
    // Get user to confirm session is active
    console.log('[Verify Token API] 🔍 Verifying session with getUser...')
    const getUserStartTime = Date.now()
    const { data: { user: verifiedUser }, error: getUserError } = await supabase.auth.getUser()
    const getUserDuration = Date.now() - getUserStartTime
    
    console.log('[Verify Token API] 📡 getUser result:', {
      duration: `${getUserDuration}ms`,
      hasUser: !!verifiedUser,
      hasError: !!getUserError,
      userId: verifiedUser?.id?.substring(0, 8) + '...',
      email: verifiedUser?.email?.substring(0, 20) + '...',
      errorMessage: getUserError?.message
    })
    
    if (getUserError || !verifiedUser) {
      console.error('[Verify Token API] ❌ Failed to get user after verification:', {
        error: getUserError?.message,
        errorStatus: getUserError?.status,
        errorCode: (getUserError as any)?.code,
        hasVerifiedUser: !!verifiedUser,
        verifyDuration: `${verifyDuration}ms`,
        getUserDuration: `${getUserDuration}ms`
      })
      return NextResponse.json({ 
        success: false, 
        message: 'Session verification failed' 
      }, { status: 500 })
    }
    
    // Update response with success data and cookies
    const totalDuration = Date.now() - startTime
    console.log('[Verify Token API] ✅ Token verified successfully, cookies set in response:', {
      userId: verifiedUser.id.substring(0, 8) + '...',
      email: verifiedUser.email?.substring(0, 20) + '...',
      verifyDuration: `${verifyDuration}ms`,
      getUserDuration: `${getUserDuration}ms`,
      totalDuration: `${totalDuration}ms`,
      cookiesSet: cookiesToSet.length,
      cookieNames: cookiesToSet.map(c => c.name),
      note: 'Cookies are set in response and will be sent to browser'
    })
    
    // Create final response with cookies
    const finalResponse = NextResponse.json({ 
      success: true, 
      user: {
        id: verifiedUser.id,
        email: verifiedUser.email
      }
    })
    
    // Copy all cookies from the response we built
    console.log('[Verify Token API] 🍪 Setting cookies in final response:', {
      cookieCount: cookiesToSet.length,
      cookies: cookiesToSet.map(c => ({
        name: c.name,
        valueLength: c.value?.length || 0,
        hasOptions: !!c.options,
        options: c.options ? {
          httpOnly: c.options.httpOnly,
          secure: c.options.secure,
          sameSite: c.options.sameSite,
          path: c.options.path,
          maxAge: c.options.maxAge,
          expires: c.options.expires ? new Date(c.options.expires).toISOString() : undefined
        } : null
      }))
    })
    
    cookiesToSet.forEach(({ name, value, options }, index) => {
      const cookieOptions = {
        ...options,
        httpOnly: options?.httpOnly ?? true,
        secure: options?.secure ?? true,
        sameSite: options?.sameSite ?? 'lax',
        path: options?.path ?? '/',
      }
      
      finalResponse.cookies.set(name, value, cookieOptions)
      
      console.log(`[Verify Token API] 🍪 Cookie ${index + 1}/${cookiesToSet.length} set:`, {
        name,
        valueLength: value?.length || 0,
        valuePrefix: value?.substring(0, 30) + '...',
        options: cookieOptions
      })
    })
    
    // Verify cookies were actually set in response
    const responseCookieHeaders = finalResponse.headers.getSetCookie()
    console.log('[Verify Token API] 📤 Response prepared with cookies:', {
      cookieCount: cookiesToSet.length,
      cookieNames: cookiesToSet.map(c => c.name),
      responseCookieHeaders: responseCookieHeaders.length,
      responseCookieHeaderNames: responseCookieHeaders.map(h => {
        const match = h.match(/^([^=]+)=/)
        return match ? match[1] : 'unknown'
      }),
      note: 'Cookies are set in response headers and will be sent to browser'
    })
    
    return finalResponse
  } catch (error) {
    const totalDuration = Date.now() - startTime
    console.error('[Verify Token API] ❌ Unexpected error:', {
      error: error instanceof Error ? error.message : String(error),
      errorStack: error instanceof Error ? error.stack : undefined,
      duration: `${totalDuration}ms`
    })
    return NextResponse.json({ 
      success: false, 
      message: error instanceof Error ? error.message : 'Unknown error' 
    }, { status: 500 })
  }
}

