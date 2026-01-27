import { createClient } from '@/lib/supabase/server'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

/**
 * Auth Callback Route - Web Handler
 * 
 * Handles authentication callbacks for web browsers.
 * 
 * Flow:
 * - If app is installed: Universal Links intercept HTTPS URLs and open app directly (bypasses this)
 * - If app is NOT installed: Opens in browser → this route handles auth and redirects to dashboard
 */

export async function GET(request: NextRequest) {
  const requestStartTime = Date.now();
  console.log('🔍 [AUTH_CALLBACK] Route handler started:', {
    url: request.url,
    pathname: request.nextUrl.pathname,
    searchParams: Object.fromEntries(request.nextUrl.searchParams),
    method: request.method,
    headers: {
      host: request.headers.get('host'),
      'x-forwarded-host': request.headers.get('x-forwarded-host'),
      'x-forwarded-proto': request.headers.get('x-forwarded-proto'),
      'user-agent': request.headers.get('user-agent')?.substring(0, 50),
    },
    timestamp: new Date().toISOString(),
  });

  const { searchParams } = new URL(request.url)
  const code = searchParams.get('code')
  const token = searchParams.get('token') // Supabase verification token
  const type = searchParams.get('type') // signup, recovery, etc.
  const next = searchParams.get('returnUrl') || searchParams.get('redirect') || '/dashboard'
  const termsAccepted = searchParams.get('terms_accepted') === 'true'
  const email = searchParams.get('email') || '' // Email passed from magic link redirect URL

  // Use request headers to determine the correct base URL
  // Priority: X-Forwarded-Host > Host > request.nextUrl.origin
  // This handles reverse proxy scenarios where origin might be 0.0.0.0:3000
  const forwardedHost = request.headers.get('x-forwarded-host');
  const host = request.headers.get('host');
  const forwardedProto = request.headers.get('x-forwarded-proto');
  
  // Determine protocol - ensure it has a colon
  let protocol: string;
  if (forwardedProto) {
    protocol = forwardedProto.includes(':') ? forwardedProto : `${forwardedProto}:`;
  } else {
    // Extract protocol from nextUrl.origin or default to https
    const origin = request.nextUrl.origin;
    if (origin && origin.includes('://')) {
      protocol = origin.split('://')[0] + ':';
    } else {
      protocol = 'https:'; // Default to https for production
    }
  }
  
  let baseUrl: string;
  if (forwardedHost) {
    baseUrl = `${protocol}//${forwardedHost}`;
  } else if (host) {
    baseUrl = `${protocol}//${host}`;
  } else {
    baseUrl = request.nextUrl.origin || process.env.NEXT_PUBLIC_URL || 'http://localhost:3000';
  }
  
  // Ensure baseUrl is valid (has protocol and host)
  if (!baseUrl.includes('://')) {
    console.warn('⚠️ Invalid baseUrl format, fixing:', baseUrl);
    baseUrl = `https://${baseUrl.replace(/^https?:\/\//, '').replace(/^https?:\//, '')}`;
  }
  
  console.log('🌐 Base URL determined:', {
    forwardedHost,
    host,
    forwardedProto,
    protocol,
    nextUrlOrigin: request.nextUrl.origin,
    finalBaseUrl: baseUrl,
  });
  const error = searchParams.get('error')
  const errorCode = searchParams.get('error_code')
  const errorDescription = searchParams.get('error_description')


  // Handle errors FIRST - before any Supabase operations that might affect session
  if (error) {
    console.error('❌ Auth callback error:', error, errorCode, errorDescription)

    // Check if the error is due to expired/invalid link
    const isExpiredOrInvalid =
      errorCode === 'otp_expired' ||
      errorCode === 'expired_token' ||
      errorCode === 'token_expired' ||
      error?.toLowerCase().includes('expired') ||
      error?.toLowerCase().includes('invalid') ||
      errorDescription?.toLowerCase().includes('expired') ||
      errorDescription?.toLowerCase().includes('invalid')

    if (isExpiredOrInvalid) {
      // Redirect to auth page with expired state to show resend form
      const expiredUrl = new URL(`${baseUrl}/auth`)
      expiredUrl.searchParams.set('expired', 'true')
      if (email) expiredUrl.searchParams.set('email', email)
      if (next) expiredUrl.searchParams.set('returnUrl', next)

      console.log('🔄 Redirecting to auth page with expired state')
      return NextResponse.redirect(expiredUrl)
    }

    // For other errors, redirect to auth page with error
    return NextResponse.redirect(`${baseUrl}/auth?error=${encodeURIComponent(error)}`)
  }

  const supabase = await createClient()

  // Log Supabase client configuration for debugging
  console.log('🔍 [AUTH_CALLBACK] Supabase client config:', {
    supabaseUrl: process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || 'not set',
    hasAnonKey: !!(process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY),
    timestamp: new Date().toISOString(),
  });

  // Check if user is already authenticated (prevent duplicate token verification)
  // This handles cases where:
  // 1. Token was already used and session was established
  // 2. Browser retries the callback URL after redirect
  // 3. Token expired but user already has a valid session
  console.log('🔍 [AUTH_CALLBACK] Checking existing session...');
  const sessionCheckStartTime = Date.now();
  
  // IMPORTANT: Check for session cookies first before calling getSession()
  // This helps identify if cookies are present but not being read correctly
  const { cookies } = await import('next/headers');
  const cookieStore = await cookies();
  const allCookies = cookieStore.getAll();
  const authCookies = allCookies.filter(c => 
    c.name.includes('supabase') || 
    c.name.includes('auth') || 
    c.name === 'sb-supabase-kong-auth-token'
  );
  
  console.log('🔍 [AUTH_CALLBACK] Auth cookies check:', {
    totalCookies: allCookies.length,
    authCookiesCount: authCookies.length,
    authCookieNames: authCookies.map(c => c.name),
    timestamp: new Date().toISOString(),
  });
  
  const { data: { session: existingSession }, error: sessionCheckError } = await supabase.auth.getSession()
  const sessionCheckDuration = Date.now() - sessionCheckStartTime;
  
  console.log('🔍 [AUTH_CALLBACK] Session check result:', {
    hasSession: !!existingSession,
    hasUser: !!existingSession?.user,
    userId: existingSession?.user?.id,
    sessionExpiresAt: existingSession?.expires_at,
    hasAuthCookies: authCookies.length > 0,
    error: sessionCheckError?.message,
    duration: `${sessionCheckDuration}ms`,
    timestamp: new Date().toISOString(),
  });
  
  // If user already authenticated, redirect immediately without processing token
  // This prevents "token already used" errors when browser retries callback
  if (existingSession && existingSession.user) {
    const redirectUrl = new URL(`${baseUrl}${next}`)
    console.log('✅ [AUTH_CALLBACK] User already authenticated, skipping token verification:', {
      userId: existingSession.user.id,
      redirectUrl: redirectUrl.toString(),
      hasSession: true,
      timestamp: new Date().toISOString(),
    });
    
    const redirectStartTime = Date.now();
    const redirectResponse = NextResponse.redirect(redirectUrl, { status: 307 })
    
    // Copy ALL cookies to redirect response to ensure session is preserved
    allCookies.forEach((cookie) => {
      redirectResponse.cookies.set(cookie.name, cookie.value);
    });
    
    redirectResponse.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    redirectResponse.headers.set('Pragma', 'no-cache');
    redirectResponse.headers.set('Expires', '0');
    
    const redirectDuration = Date.now() - redirectStartTime;
    const totalDuration = Date.now() - requestStartTime;
    
    console.log('✅ [AUTH_CALLBACK] Redirect response created for existing session:', {
      status: 307,
      redirectUrl: redirectUrl.toString(),
      cookiesInResponse: redirectResponse.cookies.getAll().map(c => c.name),
      redirectDuration: `${redirectDuration}ms`,
      totalDuration: `${totalDuration}ms`,
      timestamp: new Date().toISOString(),
    });
    
    return redirectResponse
  }
  
  // If we have auth cookies but no session, there might be a cookie issue
  // Still proceed with token verification, but log the discrepancy
  if (authCookies.length > 0 && !existingSession) {
    console.warn('⚠️ [AUTH_CALLBACK] Auth cookies present but no session found:', {
      authCookieNames: authCookies.map(c => c.name),
      timestamp: new Date().toISOString(),
    });
  }

  // Handle token-based verification (magic link PKCE token)
  // Supabase sends these to the redirect URL for processing
  if (token) {
    // Default to 'magiclink' if type is not provided (for PKCE tokens)
    const finalType = type || 'magiclink';
    
    console.log('🔍 Callback route processing token:', {
      token: token.substring(0, 20) + '...',
      type: finalType,
      hasReturnUrl: !!next,
      isPkceToken: token.startsWith('pkce_'),
    });

    try {
      // Check if this is a PKCE token (starts with "pkce_")
      // PKCE tokens should be handled as "code" for exchangeCodeForSession
      // But if exchangeCodeForSession fails (no code verifier), fall back to verifyOtp
      
      let data: any = null;
      let error: any = null;
      
      // For PKCE tokens (starting with "pkce_"), try exchangeCodeForSession first
      // This requires code verifier stored in cookies (set by @supabase/ssr)
      if (token.startsWith('pkce_')) {
        console.log('🔄 PKCE token detected, trying exchangeCodeForSession...');
        const exchangeResult = await supabase.auth.exchangeCodeForSession(token);
        
        if (exchangeResult.error) {
          console.log('⚠️ exchangeCodeForSession failed (code verifier may be missing), trying verifyOtp:', exchangeResult.error.message);
          
          // Fall back to verifyOtp - PKCE tokens can also be verified with token_hash
          // This works even if code verifier is missing
          const verifyResult = await supabase.auth.verifyOtp({
            token_hash: token,
            type: finalType as any,
          });
          
          if (verifyResult.error) {
            error = verifyResult.error;
            console.error('❌ Both PKCE verification methods failed:', {
              exchangeError: exchangeResult.error.message,
              verifyError: verifyResult.error.message,
              tokenPrefix: token.substring(0, 20),
              type: finalType,
            });
          } else {
            data = verifyResult.data;
            console.log('✅ verifyOtp with token_hash succeeded for PKCE token');
            
            // CRITICAL: After verifyOtp succeeds, immediately check if session cookies were set
            // This helps diagnose cookie setting issues
            const { cookies: checkCookies } = await import('next/headers');
            const checkCookieStore = await checkCookies();
            const checkAllCookies = checkCookieStore.getAll();
            const checkSessionCookie = checkAllCookies.find(c => 
              c.name === 'sb-supabase-kong-auth-token' || 
              (c.name.includes('supabase') && c.name.includes('auth-token') && !c.name.includes('code-verifier'))
            );
            
            console.log('🔍 [AUTH_CALLBACK] After verifyOtp success - cookie check:', {
              hasData: !!data,
              hasUser: !!data?.user,
              userId: data?.user?.id,
              cookiesAfterVerify: checkAllCookies.length,
              hasSessionCookie: !!checkSessionCookie,
              sessionCookieName: checkSessionCookie?.name,
              allCookieNames: checkAllCookies.map(c => c.name),
              timestamp: new Date().toISOString(),
            });
          }
        } else {
          data = exchangeResult.data;
          console.log('✅ exchangeCodeForSession succeeded for PKCE token');
        }
      } else {
        // Non-PKCE token - use verifyOtp directly
        console.log('🔄 Non-PKCE token detected, using verifyOtp...');
        const verifyResult = await supabase.auth.verifyOtp({
          token_hash: token,
          type: finalType as any,
        });
        
        if (verifyResult.error) {
          error = verifyResult.error;
          console.error('❌ verifyOtp failed:', {
            verifyError: verifyResult.error.message,
            tokenPrefix: token.substring(0, 20),
            type: finalType,
          });
        } else {
          data = verifyResult.data;
          console.log('✅ verifyOtp succeeded');
        }
      }

      if (error) {
        console.error('❌ [AUTH_CALLBACK] Error verifying token:', {
          error: error.message,
          errorCode: error.code,
          errorStatus: error.status,
          tokenPrefix: token?.substring(0, 20),
          type: finalType,
          timestamp: new Date().toISOString(),
        });
        
        // Check if the error is due to expired/invalid link
        const isExpired = 
          error.message?.toLowerCase().includes('expired') ||
          error.message?.toLowerCase().includes('invalid') ||
          error.status === 400 ||
          error.code === 'expired_token' ||
          error.code === 'token_expired' ||
          error.code === 'otp_expired'
        
        console.log('🔍 [AUTH_CALLBACK] Checking if error is expired/invalid:', {
          isExpired,
          errorMessage: error.message,
          errorCode: error.code,
          timestamp: new Date().toISOString(),
        });
        
        // IMPORTANT: If token expired/invalid, check if user already has a valid session
        // This handles cases where token was used successfully but browser retries the callback
        if (isExpired) {
          console.log('🔍 [AUTH_CALLBACK] Token expired/invalid, checking for existing session...');
          const sessionCheckStartTime = Date.now();
          const { data: { session: checkSession }, error: checkSessionError } = await supabase.auth.getSession();
          const sessionCheckDuration = Date.now() - sessionCheckStartTime;
          
          console.log('🔍 [AUTH_CALLBACK] Session check after token error:', {
            hasSession: !!checkSession,
            hasUser: !!checkSession?.user,
            userId: checkSession?.user?.id,
            checkError: checkSessionError?.message,
            duration: `${sessionCheckDuration}ms`,
            timestamp: new Date().toISOString(),
          });
          
          if (checkSession && checkSession.user) {
            // Token expired but user already authenticated - redirect to dashboard
            const redirectUrl = new URL(`${baseUrl}${next}`)
            console.log('✅ [AUTH_CALLBACK] Token expired but user already authenticated, redirecting to dashboard:', {
              redirectUrl: redirectUrl.toString(),
              userId: checkSession.user.id,
              timestamp: new Date().toISOString(),
            });
            
            const redirectResponse = NextResponse.redirect(redirectUrl, { status: 307 })
            
            // Copy existing cookies to redirect response
            const { cookies } = await import('next/headers');
            const cookieStore = await cookies();
            const allCookies = cookieStore.getAll();
            
            console.log('🔍 [AUTH_CALLBACK] Copying cookies for expired token redirect:', {
              cookiesCount: allCookies.length,
              cookieNames: allCookies.map(c => c.name),
              timestamp: new Date().toISOString(),
            });
            
            allCookies.forEach((cookie) => {
              redirectResponse.cookies.set(cookie.name, cookie.value);
            });
            
            redirectResponse.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate');
            redirectResponse.headers.set('Pragma', 'no-cache');
            redirectResponse.headers.set('Expires', '0');
            
            const totalDuration = Date.now() - requestStartTime;
            console.log('✅ [AUTH_CALLBACK] Redirect response created for expired token:', {
              redirectUrl: redirectUrl.toString(),
              cookiesInResponse: redirectResponse.cookies.getAll().map(c => c.name),
              totalDuration: `${totalDuration}ms`,
              timestamp: new Date().toISOString(),
            });
            
            return redirectResponse
          }
          
          // Token expired and no session - redirect to auth page with expired state
          const expiredUrl = new URL(`${baseUrl}/auth`)
          expiredUrl.searchParams.set('expired', 'true')
          if (email) expiredUrl.searchParams.set('email', email)
          if (next) expiredUrl.searchParams.set('returnUrl', next)

          const totalDuration = Date.now() - requestStartTime;
          console.log('🔄 [AUTH_CALLBACK] Token expired and no session, redirecting to auth page:', {
            expiredUrl: expiredUrl.toString(),
            email,
            returnUrl: next,
            totalDuration: `${totalDuration}ms`,
            timestamp: new Date().toISOString(),
          });
          
          return NextResponse.redirect(expiredUrl)
        }
        
        const totalDuration = Date.now() - requestStartTime;
        const errorRedirectUrl = `${baseUrl}/auth?error=${encodeURIComponent(error.message)}`;
        console.log('❌ [AUTH_CALLBACK] Token verification failed, redirecting to auth with error:', {
          errorRedirectUrl,
          error: error.message,
          totalDuration: `${totalDuration}ms`,
          timestamp: new Date().toISOString(),
        });
        
        return NextResponse.redirect(errorRedirectUrl)
      }

      // Token verified successfully, redirect to dashboard
      if (data && data.user) {
        // Determine if this is a new user (for analytics tracking)
        const createdAt = new Date(data.user.created_at).getTime();
        const now = Date.now();
        const isNewUser = (now - createdAt) < 60000; // Created within last 60 seconds
        const authEvent = isNewUser ? 'signup' : 'login';
        const authMethod = 'email';

        if (termsAccepted) {
          const currentMetadata = data.user.user_metadata || {};
          if (!currentMetadata.terms_accepted_at) {
            try {
              await supabase.auth.updateUser({
                data: {
                  ...currentMetadata,
                  terms_accepted_at: new Date().toISOString(),
                },
              });
              console.log('✅ Terms acceptance date saved to user metadata');
            } catch (updateError) {
              console.warn('⚠️ Failed to save terms acceptance:', updateError);
            }
          }
        }

        // CRITICAL: After token verification, Supabase should have set session cookies
        // But we need to explicitly call getSession() to trigger cookie setting via setAll
        // Then we need to ensure those cookies are copied to the redirect response
        console.log('🔍 [AUTH_CALLBACK] Getting session after token verification...');
        const sessionGetStartTime = Date.now();
        
        // Call getSession() to trigger Supabase to set session cookies via setAll
        // This is critical - without this, session cookies won't be set
        const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
        const sessionGetDuration = Date.now() - sessionGetStartTime;
        
        if (sessionError) {
          console.error('❌ [AUTH_CALLBACK] Error getting session after token verification:', {
            error: sessionError.message,
            errorCode: sessionError.status,
            duration: `${sessionGetDuration}ms`,
            timestamp: new Date().toISOString(),
          });
        } else {
          console.log('✅ [AUTH_CALLBACK] Session established:', {
            hasSession: !!sessionData.session,
            userId: sessionData.session?.user?.id,
            sessionExpiresAt: sessionData.session?.expires_at,
            accessTokenLength: sessionData.session?.access_token?.length,
            refreshTokenLength: sessionData.session?.refresh_token?.length,
            duration: `${sessionGetDuration}ms`,
            timestamp: new Date().toISOString(),
          });
        }

        // IMPORTANT: After getSession(), Supabase's setAll should have been called
        // Now get cookies from the cookie store to capture what was set
        console.log('🔍 [AUTH_CALLBACK] Getting cookies from cookie store after session establishment...');
        const cookieGetStartTime = Date.now();
        
        // Create a fresh cookie store instance to get the latest cookies
        // This ensures we capture cookies that were just set by Supabase's setAll
        const cookieStoreAfterSession = await cookies();
        const allCookies = cookieStoreAfterSession.getAll();
        const cookieGetDuration = Date.now() - cookieGetStartTime;
        
        console.log('🔍 [AUTH_CALLBACK] Cookies retrieved:', {
          cookiesCount: allCookies.length,
          cookieNames: allCookies.map(c => c.name),
          authCookies: allCookies.filter(c => c.name.includes('supabase') || c.name.includes('auth')).map(c => ({
            name: c.name,
            valueLength: c.value.length,
          })),
          duration: `${cookieGetDuration}ms`,
          timestamp: new Date().toISOString(),
        });
        
        // Redirect to dashboard with auth tracking params
        const redirectUrl = new URL(`${baseUrl}${next}`)
        redirectUrl.searchParams.set('auth_event', authEvent)
        redirectUrl.searchParams.set('auth_method', authMethod)
        
        console.log('🔍 [AUTH_CALLBACK] Creating redirect response...', {
          redirectUrl: redirectUrl.toString(),
          authEvent,
          authMethod,
          timestamp: new Date().toISOString(),
        });
        
        // Create redirect response with proper status code
        // Use 307 (Temporary Redirect) instead of default 302 to preserve POST method and cookies
        const redirectCreateStartTime = Date.now();
        const redirectResponse = NextResponse.redirect(redirectUrl, { status: 307 })
        const redirectCreateDuration = Date.now() - redirectCreateStartTime;
        
        console.log('🔍 [AUTH_CALLBACK] Redirect response created, copying cookies...', {
          status: 307,
          redirectUrl: redirectUrl.toString(),
          redirectCreateDuration: `${redirectCreateDuration}ms`,
          timestamp: new Date().toISOString(),
        });
        
        // CRITICAL: In Next.js App Router Route Handlers, cookies set via cookies().set() 
        // are NOT automatically included in NextResponse.redirect() responses.
        // We MUST explicitly copy all cookies to the redirect response.
        // This ensures the browser receives the session cookies when following the redirect.
        const cookieCopyStartTime = Date.now();
        
        console.log('🍪 [AUTH_CALLBACK] Copying cookies to redirect response:', {
          cookiesToCopy: allCookies.length,
          cookieNames: allCookies.map(c => c.name),
          authCookies: allCookies.filter(c => 
            c.name.includes('supabase') || 
            c.name.includes('auth') || 
            c.name === 'sb-supabase-kong-auth-token'
          ).map(c => ({
            name: c.name,
            valueLength: c.value.length,
          })),
          timestamp: new Date().toISOString(),
        });
        
        // CRITICAL: Only copy the ESSENTIAL session cookie to minimize header size
        // Other cookies (code-verifier, etc.) are not needed for the redirect
        // The browser will preserve existing cookies automatically
        // This prevents "upstream sent too big header" 502 errors
        
        // Find the main session cookie (the one that actually contains the session)
        // CRITICAL: Only copy the session cookie, NOT code-verifier
        // The PKCE flow is complete after token verification, so code-verifier is no longer needed
        // This minimizes response header size and prevents 502 errors
        const sessionCookie = allCookies.find(c => 
          c.name === 'sb-supabase-kong-auth-token' ||
          (c.name.includes('supabase') && c.name.includes('auth-token') && !c.name.includes('code-verifier'))
        );
        
        // Only include the session cookie (skip code-verifier to minimize header size)
        const essentialCookies = sessionCookie && sessionCookie.value && sessionCookie.value.length > 0
          ? [sessionCookie]
          : [];
        
        console.log('🍪 [AUTH_CALLBACK] Filtering cookies to copy (minimizing header size):', {
          totalCookies: allCookies.length,
          essentialCookiesCount: essentialCookies.length,
          essentialCookieNames: essentialCookies.map(c => c.name),
          sessionCookieName: sessionCookie?.name,
          sessionCookieLength: sessionCookie?.value?.length || 0,
          skippedCookies: allCookies.length - essentialCookies.length,
          skippedCookieNames: allCookies.filter(c => !essentialCookies.includes(c)).map(c => c.name),
          timestamp: new Date().toISOString(),
        });
        
        let cookiesCopied = 0;
        let cookiesFailed = 0;
        
        essentialCookies.forEach((cookie) => {
          try {
            // Minimize cookie options to reduce header size
            // Use minimal options - path and sameSite are most important
            redirectResponse.cookies.set(cookie.name, cookie.value, {
              path: '/',
              sameSite: 'lax' as const,
              // Only set httpOnly for session cookie, not code-verifier
              httpOnly: cookie.name.includes('auth-token') && !cookie.name.includes('code-verifier'),
              secure: process.env.NODE_ENV === 'production',
              // Don't set maxAge, expires, or domain - keep it minimal
            });
            cookiesCopied++;
          } catch (error) {
            cookiesFailed++;
            console.error(`❌ [AUTH_CALLBACK] Failed to copy cookie ${cookie.name}:`, {
              error: error instanceof Error ? error.message : String(error),
              cookieName: cookie.name,
              valueLength: cookie.value?.length || 0,
              timestamp: new Date().toISOString(),
            });
          }
        });
        
        const cookieCopyDuration = Date.now() - cookieCopyStartTime;
        
        console.log('🍪 [AUTH_CALLBACK] Cookies copied to redirect response:', {
          cookiesCopied,
          cookiesFailed,
          totalCookiesInResponse: redirectResponse.cookies.getAll().length,
          cookieNames: redirectResponse.cookies.getAll().map(c => c.name),
          duration: `${cookieCopyDuration}ms`,
          timestamp: new Date().toISOString(),
        });
        
        // Set additional headers to prevent caching issues and ensure proper redirect handling
        redirectResponse.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        redirectResponse.headers.set('Pragma', 'no-cache');
        redirectResponse.headers.set('Expires', '0');
        redirectResponse.headers.set('X-Robots-Tag', 'noindex, nofollow');
        
        // Ensure redirect URL is absolute and valid
        if (!redirectUrl.toString().startsWith('http')) {
          console.error('❌ [AUTH_CALLBACK] Invalid redirect URL:', redirectUrl.toString());
          const fallbackUrl = new URL('/dashboard', baseUrl);
          return NextResponse.redirect(fallbackUrl, { status: 307 });
        }
        
        const totalDuration = Date.now() - requestStartTime;
        
        console.log('✅ [AUTH_CALLBACK] Token verified successfully, redirecting:', {
          redirectUrl: redirectUrl.toString(),
          cookiesCount: allCookies.length,
          cookieNames: allCookies.map(c => c.name).filter(name => name.includes('supabase') || name.includes('auth')),
          cookiesInResponse: redirectResponse.cookies.getAll().map(c => c.name).filter(name => name.includes('supabase') || name.includes('auth')),
          responseHeaders: Object.fromEntries(redirectResponse.headers.entries()),
          durations: {
            sessionGet: `${sessionGetDuration}ms`,
            cookieGet: `${cookieGetDuration}ms`,
            redirectCreate: `${redirectCreateDuration}ms`,
            cookieCopy: `${cookieCopyDuration}ms`,
            total: `${totalDuration}ms`,
          },
          timestamp: new Date().toISOString(),
        });
        
        return redirectResponse
      } else {
        // Token verification succeeded but no user data returned
        console.error('⚠️ Token verification succeeded but no user data:', {
          hasData: !!data,
          dataKeys: data ? Object.keys(data) : [],
        });
        
        // Redirect to auth page with error
        const errorUrl = new URL(`${baseUrl}/auth`);
        errorUrl.searchParams.set('error', 'Token verification succeeded but no user data returned');
        if (next) errorUrl.searchParams.set('returnUrl', next);
        
        return NextResponse.redirect(errorUrl);
      }
    } catch (error: any) {
      console.error('❌ Unexpected error verifying token:', {
        error: error?.message || error,
        errorDetail: error?.detail || error?.response?.data || error,
        stack: error?.stack,
        tokenPrefix: token?.substring(0, 20),
        type: finalType,
      });
      
      // If error contains "Not Found", it might be a routing issue
      // Try to provide more helpful error message
      const errorMessage = error?.detail || error?.message || 'Unknown error';
      const isNotFound = errorMessage.includes('Not Found') || errorMessage.includes('404');
      
      if (isNotFound) {
        console.error('⚠️ "Not Found" error - this might indicate:');
        console.error('   1. Supabase API endpoint issue');
        console.error('   2. Token format incorrect');
        console.error('   3. Route not properly deployed');
      }
      
      // Fallback: redirect to auth page with token for client-side handling
    const verifyUrl = new URL(`${baseUrl}/auth`)
    verifyUrl.searchParams.set('token', token)
      verifyUrl.searchParams.set('type', finalType)
    if (termsAccepted) verifyUrl.searchParams.set('terms_accepted', 'true')
      if (next) verifyUrl.searchParams.set('returnUrl', next)
      if (errorMessage) verifyUrl.searchParams.set('error', encodeURIComponent(errorMessage))
    
    return NextResponse.redirect(verifyUrl)
    }
  }

  // Handle code exchange (OAuth, magic link)
  if (code) {
    console.log('🔍 [AUTH_CALLBACK] Processing code parameter:', {
      codePrefix: code.substring(0, 20) + '...',
      codeLength: code.length,
      timestamp: new Date().toISOString(),
    });
    
    try {
      const codeExchangeStartTime = Date.now();
      const { data, error } = await supabase.auth.exchangeCodeForSession(code)
      const codeExchangeDuration = Date.now() - codeExchangeStartTime;
      
      console.log('🔍 [AUTH_CALLBACK] Code exchange result:', {
        success: !error,
        hasData: !!data,
        hasUser: !!data?.user,
        error: error?.message,
        errorCode: error?.code,
        duration: `${codeExchangeDuration}ms`,
        timestamp: new Date().toISOString(),
      });
      
      if (error) {
        console.error('❌ Error exchanging code for session:', error)
        
        // Check if the error is due to expired/invalid link
        const isExpired = 
          error.message?.toLowerCase().includes('expired') ||
          error.message?.toLowerCase().includes('invalid') ||
          error.status === 400 ||
          error.code === 'expired_token' ||
          error.code === 'token_expired' ||
          error.code === 'otp_expired'
        
        if (isExpired) {
          // Redirect to auth page with expired state to show resend form
          const expiredUrl = new URL(`${baseUrl}/auth`)
          expiredUrl.searchParams.set('expired', 'true')
          if (email) expiredUrl.searchParams.set('email', email)
          if (next) expiredUrl.searchParams.set('returnUrl', next)

          console.log('🔄 Redirecting to auth page with expired state')
          return NextResponse.redirect(expiredUrl)
        }
        
        return NextResponse.redirect(`${baseUrl}/auth?error=${encodeURIComponent(error.message)}`)
      }

      let finalDestination = next
      let shouldClearReferralCookie = false
      let authEvent = 'login'
      let authMethod = 'email'

      if (data.user) {
        // Determine if this is a new user (for analytics tracking)
        const createdAt = new Date(data.user.created_at).getTime();
        const now = Date.now();
        const isNewUser = (now - createdAt) < 60000; // Created within last 60 seconds
        authEvent = isNewUser ? 'signup' : 'login';
        authMethod = data.user.app_metadata?.provider || 'email';
        
        const pendingReferralCode = request.cookies.get('pending-referral-code')?.value
        if (pendingReferralCode) {
          try {
            await supabase.auth.updateUser({
              data: {
                referral_code: pendingReferralCode
              }
            })
            console.log('✅ Added referral code to OAuth user:', pendingReferralCode)
            shouldClearReferralCookie = true
          } catch (error) {
            console.error('Failed to add referral code to OAuth user:', error)
          }
        }

        if (termsAccepted) {
          const currentMetadata = data.user.user_metadata || {};
          if (!currentMetadata.terms_accepted_at) {
            try {
              await supabase.auth.updateUser({
                data: {
                  ...currentMetadata,
                  terms_accepted_at: new Date().toISOString(),
                },
              });
              console.log('✅ Terms acceptance date saved to user metadata');
            } catch (updateError) {
              console.warn('⚠️ Failed to save terms acceptance:', updateError);
            }
          }
        }

        const { data: accountData } = await supabase
          .schema('basejump')
          .from('accounts')
          .select('id, created_at')
          .eq('primary_owner_user_id', data.user.id)
          .eq('personal_account', true)
          .single();

        if (accountData) {
          const { data: creditAccount } = await supabase
            .from('credit_accounts')
            .select('tier, stripe_subscription_id')
            .eq('account_id', accountData.id)
            .single();

          // Only redirect to setting-up if no subscription exists (webhook failed or old user)
          if (creditAccount && (creditAccount.tier === 'none' || !creditAccount.stripe_subscription_id)) {
            console.log('⚠️ No subscription detected - redirecting to setting-up (fallback)');
            finalDestination = '/setting-up'
          } else {
            console.log('✅ Account already initialized via webhook');
          }
        }
      }

      // Web redirect - include auth event params for client-side tracking
      const redirectUrl = new URL(`${baseUrl}${finalDestination}`)
      redirectUrl.searchParams.set('auth_event', authEvent)
      redirectUrl.searchParams.set('auth_method', authMethod)
      const response = NextResponse.redirect(redirectUrl)

      // Clear referral cookie if it was processed
      if (shouldClearReferralCookie) {
        response.cookies.set('pending-referral-code', '', { maxAge: 0, path: '/' })
      }

      const totalDuration = Date.now() - requestStartTime;
      console.log('✅ [AUTH_CALLBACK] Code exchange successful, redirecting:', {
        redirectUrl: redirectUrl.toString(),
        authEvent,
        authMethod,
        totalDuration: `${totalDuration}ms`,
        timestamp: new Date().toISOString(),
      });

      return response
    } catch (error: any) {
      const totalDuration = Date.now() - requestStartTime;
      console.error('❌ [AUTH_CALLBACK] Unexpected error in auth callback:', {
        error: error?.message || error,
        errorStack: error?.stack,
        errorCode: error?.code,
        totalDuration: `${totalDuration}ms`,
        timestamp: new Date().toISOString(),
      });
      
      const errorRedirectUrl = `${baseUrl}/auth?error=unexpected_error`;
      console.log('🔄 [AUTH_CALLBACK] Redirecting to auth page with error:', {
        errorRedirectUrl,
        timestamp: new Date().toISOString(),
      });
      
      return NextResponse.redirect(errorRedirectUrl)
    }
  }
  
  // No code or token - redirect to auth page
  const totalDuration = Date.now() - requestStartTime;
  console.log('⚠️ [AUTH_CALLBACK] No code or token provided in callback URL:', {
    url: request.url,
    searchParams: Object.fromEntries(request.nextUrl.searchParams),
    totalDuration: `${totalDuration}ms`,
    timestamp: new Date().toISOString(),
  });
  
  const authRedirectUrl = `${baseUrl}/auth`;
  console.log('🔄 [AUTH_CALLBACK] Redirecting to auth page:', {
    authRedirectUrl,
    timestamp: new Date().toISOString(),
  });
  
  return NextResponse.redirect(authRedirectUrl)
}
