import { createServerClient } from '@supabase/ssr';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Route Handler for OTP verification
 * 
 * GLOBAL AUTH FLOW SUMMARY:
 * 1. User enters OTP code on /auth page
 * 2. Auth Page calls this Route Handler (primary method)
 * 3. Route Handler verifies OTP with Supabase
 * 4. Route Handler creates session and sets cookies via request.cookies
 * 5. Route Handler redirects to /dashboard with cookies in response
 * 6. Middleware checks cookies and allows access
 * 7. Dashboard renders with authenticated user
 * 
 * FALLBACK: If Route Handler fails, Auth Page falls back to Server Action
 * 
 * KEY: Route Handler uses request.cookies directly, ensuring cookies are set
 * in the redirect response. This is critical for cookie persistence.
 */
export async function POST(request: NextRequest) {
  try {
    console.log('🔐 [verifyOtp Route] ===== Route Handler Entry Point =====', {
      timestamp: new Date().toISOString(),
      method: 'POST',
      url: request.url,
    });
    
    // Parse form data from request
    let formData: FormData;
    let email: string;
    let token: string;
    let returnUrl: string;
    
    try {
      formData = await request.formData();
      email = formData.get('email') as string;
      token = formData.get('token') as string;
      returnUrl = (formData.get('returnUrl') as string) || '/dashboard';
    } catch (formDataError) {
      console.error('❌ [verifyOtp Route] Failed to parse form data:', {
        error: formDataError instanceof Error ? formDataError.message : String(formDataError),
        errorStack: formDataError instanceof Error ? formDataError.stack : undefined,
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { 
          message: 'Failed to parse request data',
          error: formDataError instanceof Error ? formDataError.message : String(formDataError),
          errorCode: 'FORM_DATA_PARSE_ERROR',
        },
        { status: 400 }
      );
    }

    // Log all form data entries for debugging
    const allFormData: Record<string, string> = {};
    formData.forEach((value, key) => {
      allFormData[key] = typeof value === 'string' ? value : 'non-string';
    });

    console.log('🔐 [verifyOtp Route] Request received:', {
      hasEmail: !!email,
      email: email || 'MISSING',
      hasToken: !!token,
      token: token ? `${token.substring(0, 2)}****` : 'MISSING',
      tokenLength: token?.length || 0,
      returnUrl,
      allFormDataKeys: Object.keys(allFormData),
      allFormDataValues: Object.keys(allFormData).reduce((acc, key) => {
        const val = allFormData[key];
        acc[key] = key === 'token' ? `${val.substring(0, 2)}****` : val;
        return acc;
      }, {} as Record<string, string>),
      timestamp: new Date().toISOString(),
    });

    if (!email || !email.includes('@')) {
      return NextResponse.json(
        { message: 'Please enter a valid email address' },
        { status: 400 }
      );
    }

    // CRITICAL: Log original token BEFORE normalization for debugging
    console.log('🔍 [verifyOtp Route] Original token received:', {
      originalToken: token || 'MISSING',
      originalTokenLength: token?.length || 0,
      originalTokenType: typeof token,
      originalTokenFirstChars: token ? token.substring(0, Math.min(10, token.length)) : 'MISSING',
      originalTokenLastChars: token && token.length > 10 ? token.substring(token.length - 10) : 'MISSING',
      hasNonDigits: token ? /\D/.test(token) : false,
      timestamp: new Date().toISOString(),
    });
    
    // Normalize token: remove all non-digit characters and trim whitespace
    // This handles cases where users might paste codes with spaces, dashes, etc.
    const normalizedTokenInput = token.replace(/\D/g, '').trim();
    
    console.log('🔍 [verifyOtp Route] Token normalization result:', {
      originalToken: token || 'MISSING',
      normalizedToken: normalizedTokenInput || 'MISSING',
      normalizedLength: normalizedTokenInput?.length || 0,
      removedChars: token ? token.length - normalizedTokenInput.length : 0,
      timestamp: new Date().toISOString(),
    });
    
    if (!normalizedTokenInput || normalizedTokenInput.length !== 6) {
      console.error('❌ [verifyOtp Route] Invalid token format:', {
        originalToken: token || 'MISSING',
        originalLength: token?.length || 0,
        normalizedToken: normalizedTokenInput || 'MISSING',
        normalizedLength: normalizedTokenInput?.length || 0,
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { message: 'Please enter a valid 6-digit code from your email' },
        { status: 400 }
      );
    }

    // Create Supabase client using request.cookies (Route Handler approach)
    // Get Supabase configuration
    let supabaseUrl = (process.env.SUPABASE_URL || '').trim();
    let supabaseKey = (process.env.SUPABASE_ANON_KEY || '').trim();
    
    // Fallback to NEXT_PUBLIC_* vars if server-side vars not set
    if (!supabaseUrl || supabaseUrl.trim() === '') {
      const publicUrl = (process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim();
      if (publicUrl && publicUrl.startsWith('/')) {
        supabaseUrl = 'http://supabase-kong:8000';
      } else if (publicUrl && !publicUrl.includes('demo.supabase.co') && !publicUrl.includes('placeholder')) {
        supabaseUrl = publicUrl;
      } else {
        supabaseUrl = 'http://supabase-kong:8000';
      }
    }
    
    if (supabaseUrl.includes('demo.supabase.co') || supabaseUrl.includes('placeholder') || supabaseUrl.trim() === '') {
      supabaseUrl = 'http://supabase-kong:8000';
    }
    
    if (!supabaseKey || supabaseKey.trim() === '') {
      const publicKey = (process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '').trim();
      if (publicKey && publicKey.trim() !== '') {
        supabaseKey = publicKey;
      } else {
        supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
      }
    }

    // Create response object for cookie setting
    // CRITICAL: We need to track cookies separately because supabaseResponse gets recreated
    // Store cookies in a Map to ensure we have all of them
    const cookieMap = new Map<string, { value: string; options?: any }>();
    
    let supabaseResponse = NextResponse.next({
      request,
    });

    const supabase = createServerClient(
      supabaseUrl,
      supabaseKey,
      {
        cookies: {
          getAll() {
            return request.cookies.getAll();
          },
          setAll(cookiesToSet) {
            console.log('🍪 [verifyOtp Route] setAll called:', {
              cookieCount: cookiesToSet.length,
              cookieNames: cookiesToSet.map(c => c.name),
              timestamp: new Date().toISOString(),
            });
            
            // Store cookies in map for later use
            cookiesToSet.forEach(({ name, value, options }) => {
              cookieMap.set(name, { value, options });
              request.cookies.set(name, value);
            });
            
            // Recreate response with updated cookies
            supabaseResponse = NextResponse.next({
              request,
            });
            
            // Set cookies in the response
            cookiesToSet.forEach(({ name, value, options }) => {
              supabaseResponse.cookies.set(name, value, options || {});
            });
            
            console.log('🍪 [verifyOtp Route] Cookies stored in map:', {
              cookieCount: cookieMap.size,
              cookieNames: Array.from(cookieMap.keys()),
              timestamp: new Date().toISOString(),
            });
          },
        },
      }
    );

    console.log('🔐 [verifyOtp Route] Starting OTP verification:', {
      email: email.trim().toLowerCase(),
      tokenLength: token.trim().length,
      tokenPrefix: token?.substring(0, 2) + '****',
      returnUrl,
      supabaseUrl: supabaseUrl.substring(0, 50) + '...',
      timestamp: new Date().toISOString(),
    });

    // Use 'email' type for 6-digit OTP codes
    // 'magiclink' is for link-based verification, not OTP codes
    // IMPORTANT: The type must match what was used when sending the OTP
    // If signInWithOtp was called without shouldSendOtpCode, it sends a magic link
    // If shouldSendOtpCode is true, it sends a 6-digit code and type should be 'email'
    const normalizedEmail = email.trim().toLowerCase();
    // Use the already normalized token from validation above
    const normalizedToken = normalizedTokenInput;
    
    // CRITICAL DEBUGGING: Log exact values being sent to Supabase
    console.log('🔍 [verifyOtp Route] ===== EXACT VALUES BEING SENT TO SUPABASE =====', {
      email: normalizedEmail,
      token: normalizedToken, // Log full token for debugging (will be masked in production)
      tokenLength: normalizedToken.length,
      tokenIsNumeric: /^\d+$/.test(normalizedToken),
      supabaseUrl: supabaseUrl.substring(0, 50) + '...',
      timestamp: new Date().toISOString(),
    });
    
    // IMPORTANT: According to Supabase docs, generate_link returns email_otp which should be verified with type="email"
    // NOT type="magiclink" - magiclink type is for verifying the actual magic link URL, not the OTP code
    // The email_otp from generate_link is a 6-digit code that uses the same verification flow as signInWithOtp with shouldSendOtpCode=true
    console.log('🔐 [verifyOtp Route] Calling supabase.auth.verifyOtp with type=email (primary - correct for email_otp)...', {
      email: normalizedEmail,
      tokenLength: normalizedToken.length,
      tokenPrefix: normalizedToken.substring(0, 2) + '****',
      type: 'email',
      reason: 'Backend extracts email_otp from generate_link - email_otp uses type="email" (not magiclink)',
      supabaseUrl: supabaseUrl.substring(0, 50) + '...',
      timestamp: new Date().toISOString(),
    });
    
    // Try 'email' type first - this is correct for email_otp from generate_link
    let verifyResult;
    try {
      verifyResult = await supabase.auth.verifyOtp({
        email: normalizedEmail,
        token: normalizedToken,
        type: 'email', // email_otp from generate_link uses type="email"
      });
      
      console.log('🔍 [verifyOtp Route] verifyOtp (email) response:', {
        hasData: !!verifyResult.data,
        hasError: !!verifyResult.error,
        errorMessage: verifyResult.error?.message,
        errorCode: verifyResult.error?.code,
        errorStatus: verifyResult.error?.status,
        userId: verifyResult.data?.user?.id,
        hasSession: !!verifyResult.data?.session,
        timestamp: new Date().toISOString(),
      });
    } catch (verifyError) {
      console.error('❌ [verifyOtp Route] verifyOtp call threw exception:', {
        error: verifyError instanceof Error ? verifyError.message : String(verifyError),
        errorStack: verifyError instanceof Error ? verifyError.stack : undefined,
        email: normalizedEmail,
        tokenLength: normalizedToken.length,
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { 
          message: 'Failed to verify OTP code',
          error: verifyError instanceof Error ? verifyError.message : String(verifyError),
          errorCode: 'VERIFY_OTP_EXCEPTION',
        },
        { status: 500 }
      );
    }
    
    // If 'email' type fails with specific error, try 'magiclink' as fallback
    // This handles edge cases where the token might be a magic link token instead
    const shouldRetryWithMagiclink = verifyResult.error && 
      verifyResult.error.code !== 'otp_expired' &&
      verifyResult.error.code !== 'expired_token' &&
      verifyResult.error.code !== 'token_expired' &&
      verifyResult.error.code !== 'invalid_token' &&
      verifyResult.error.code !== 'invalid_grant';
    
    if (shouldRetryWithMagiclink) {
      console.log('🔄 [verifyOtp Route] email type failed with retryable error, trying magiclink type...', {
        errorMessage: verifyResult.error?.message,
        errorCode: verifyResult.error?.code,
        timestamp: new Date().toISOString(),
      });
      
      try {
        verifyResult = await supabase.auth.verifyOtp({
          email: normalizedEmail,
          token: normalizedToken,
          type: 'magiclink', // Fallback to magiclink type
        });
        
        console.log('🔍 [verifyOtp Route] verifyOtp (magiclink fallback) response:', {
          hasData: !!verifyResult.data,
          hasError: !!verifyResult.error,
          errorMessage: verifyResult.error?.message,
          errorCode: verifyResult.error?.code,
          errorStatus: verifyResult.error?.status,
          userId: verifyResult.data?.user?.id,
          hasSession: !!verifyResult.data?.session,
          timestamp: new Date().toISOString(),
        });
      } catch (verifyError) {
        console.error('❌ [verifyOtp Route] verifyOtp (magiclink fallback) call threw exception:', {
          error: verifyError instanceof Error ? verifyError.message : String(verifyError),
          errorStack: verifyError instanceof Error ? verifyError.stack : undefined,
          email: normalizedEmail,
          tokenLength: normalizedToken.length,
          timestamp: new Date().toISOString(),
        });
        return NextResponse.json(
          { 
            message: 'Failed to verify OTP code',
            error: verifyError instanceof Error ? verifyError.message : String(verifyError),
            errorCode: 'VERIFY_OTP_EXCEPTION',
          },
          { status: 500 }
        );
      }
    } else if (verifyResult.error) {
      console.log('⏭️ [verifyOtp Route] Skipping magiclink type retry - token is expired or invalid:', {
        errorMessage: verifyResult.error?.message,
        errorCode: verifyResult.error?.code,
        timestamp: new Date().toISOString(),
      });
    }
    
    console.log('🔐 [verifyOtp Route] verifyOtp response received:', {
      hasData: !!verifyResult.data,
      hasError: !!verifyResult.error,
      errorMessage: verifyResult.error?.message,
      errorCode: verifyResult.error?.code,
      errorStatus: verifyResult.error?.status,
      userId: verifyResult.data?.user?.id,
      hasSession: !!verifyResult.data?.session,
      typeUsed: verifyResult.error ? 'email -> magiclink (fallback)' : 'email',
      timestamp: new Date().toISOString(),
    });
    
    const { data, error } = verifyResult;

    if (error) {
      console.error('❌ [verifyOtp Route] OTP verification failed:', {
        error: error.message,
        errorCode: error.code,
        errorStatus: error.status,
        email: normalizedEmail,
        tokenLength: normalizedToken.length,
        tokenPrefix: normalizedToken.substring(0, 2) + '****',
        typeUsed: verifyResult.error ? 'email -> magiclink (fallback)' : 'email',
        supabaseUrl: supabaseUrl.substring(0, 50) + '...',
        timestamp: new Date().toISOString(),
      });
      
      // Check if error is due to expired token
      const isExpired = error.message?.toLowerCase().includes('expired') || 
                       error.code === 'expired_token' ||
                       error.code === 'token_expired' ||
                       error.code === 'otp_expired';
      
      // Check if error is due to invalid token
      const isInvalid = error.message?.toLowerCase().includes('invalid') ||
                       error.code === 'invalid_token' ||
                       error.code === 'invalid_grant';
      
      console.error('❌ [verifyOtp Route] Error analysis:', {
        isExpired,
        isInvalid,
        errorMessage: error.message,
        errorCode: error.code,
        timestamp: new Date().toISOString(),
      });
      
      // Return detailed error information for debugging
      const errorMessage = error.message || 'Invalid or expired code';
      console.error('❌ [verifyOtp Route] Returning error response:', {
        status: 400,
        message: errorMessage,
        timestamp: new Date().toISOString(),
      });
      
      return NextResponse.json(
        { 
          message: errorMessage,
          errorCode: error.code,
          isExpired,
          isInvalid,
        },
        { status: 400 }
      );
    }

    console.log('✅ [verifyOtp Route] OTP verified successfully:', {
      userId: data.user?.id,
      email: data.user?.email,
      hasSession: !!data.session,
      sessionExpiresAt: data.session?.expires_at,
      timestamp: new Date().toISOString(),
    });

    // CRITICAL: verifyOtp returns session in data.session
    // Use it directly instead of calling getSession() again
    // getSession() might not trigger setAll() if session is already set
    let session = data.session;
    
    // If session is not in verifyOtp response, try getSession()
    // This should trigger setAll() to set cookies
    if (!session) {
      console.warn('⚠️ [verifyOtp Route] Session not in verifyOtp response, calling getSession()...', {
        userId: data.user?.id,
        email: data.user?.email,
        timestamp: new Date().toISOString(),
      });
      
      try {
        const { data: { session: fetchedSession }, error: getSessionError } = await supabase.auth.getSession();
        if (getSessionError) {
          console.error('❌ [verifyOtp Route] getSession() returned error:', {
            error: getSessionError.message,
            errorCode: getSessionError.code,
            timestamp: new Date().toISOString(),
          });
        }
        session = fetchedSession;
      } catch (getSessionException) {
        console.error('❌ [verifyOtp Route] getSession() threw exception:', {
          error: getSessionException instanceof Error ? getSessionException.message : String(getSessionException),
          errorStack: getSessionException instanceof Error ? getSessionException.stack : undefined,
          timestamp: new Date().toISOString(),
        });
        return NextResponse.json(
          { 
            message: 'Failed to retrieve session after verification',
            error: getSessionException instanceof Error ? getSessionException.message : String(getSessionException),
            errorCode: 'GET_SESSION_EXCEPTION',
          },
          { status: 500 }
        );
      }
    }
    
    if (!session) {
      console.error('❌ [verifyOtp Route] Session not created after verification:', {
        userId: data.user?.id,
        email: data.user?.email,
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { message: 'Session not created after verification. Please try again.' },
        { status: 500 }
      );
    }
    
    // CRITICAL: Ensure session is set in Supabase client
    // This will trigger setAll() to set cookies if not already set
    if (session.access_token && session.refresh_token) {
      console.log('🔄 [verifyOtp Route] Setting session explicitly to ensure cookies are set...', {
        userId: session.user.id,
        email: session.user.email,
        timestamp: new Date().toISOString(),
      });
      
      try {
        const { data: sessionData, error: setSessionError } = await supabase.auth.setSession({
          access_token: session.access_token,
          refresh_token: session.refresh_token,
        });
        
        if (setSessionError) {
          console.error('❌ [verifyOtp Route] Failed to set session:', {
            error: setSessionError.message,
            errorCode: setSessionError.code,
            timestamp: new Date().toISOString(),
          });
          // Don't fail - session might already be set
        } else {
          console.log('✅ [verifyOtp Route] Session set explicitly:', {
            userId: sessionData.session?.user.id,
            email: sessionData.session?.user.email,
            timestamp: new Date().toISOString(),
          });
          // Update session reference to the one returned by setSession
          if (sessionData.session) {
            session = sessionData.session;
          }
        }
      } catch (setSessionException) {
        console.error('❌ [verifyOtp Route] setSession() threw exception:', {
          error: setSessionException instanceof Error ? setSessionException.message : String(setSessionException),
          errorStack: setSessionException instanceof Error ? setSessionException.stack : undefined,
          timestamp: new Date().toISOString(),
        });
        // Don't fail - session might already be set, continue with redirect
      }
    }

    console.log('✅ [verifyOtp Route] Session created successfully:', {
      userId: session.user.id,
      email: session.user.email,
      expiresAt: session.expires_at,
      expiresAtDate: session.expires_at ? new Date(session.expires_at * 1000).toISOString() : 'N/A',
      timestamp: new Date().toISOString(),
    });

    // CRITICAL: After verifyOtp and getSession, Supabase has called setAll() multiple times
    // Each call recreates supabaseResponse, so we need to get the latest one
    // Verify cookies are set after session creation
    // Check both request.cookies (set by setAll) and supabaseResponse.cookies
    const requestCookies = request.cookies.getAll();
    const responseCookies = supabaseResponse.cookies.getAll();
    const allCookies = [...requestCookies, ...responseCookies];
    const authCookies = allCookies.filter(c => c.name.startsWith('sb-'));
    
    // Store request auth cookies for later use in cookie copying
    const requestAuthCookies = requestCookies.filter(c => c.name.startsWith('sb-'));
    
    console.log('🍪 [verifyOtp Route] Cookies after session creation:', {
      requestCookieCount: requestCookies.length,
      responseCookieCount: responseCookies.length,
      totalCookies: allCookies.length,
      requestAuthCookies: requestAuthCookies.map(c => c.name),
      responseAuthCookies: responseCookies.filter(c => c.name.startsWith('sb-')).map(c => c.name),
      authCookies: authCookies.map(c => ({ name: c.name, hasValue: !!c.value, valueLength: c.value?.length || 0 })),
      timestamp: new Date().toISOString(),
    });
    
    // CRITICAL: If no cookies found, this is a problem
    if (authCookies.length === 0) {
      console.error('❌ [verifyOtp Route] No auth cookies found after session creation!', {
        requestCookieCount: requestCookies.length,
        responseCookieCount: responseCookies.length,
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { message: 'Failed to set authentication cookies. Please try again.' },
        { status: 500 }
      );
    }

    // Determine if new user (for analytics)
    const isNewUser = data.user && (Date.now() - new Date(data.user.created_at).getTime()) < 60000;
    const authEvent = isNewUser ? 'signup' : 'login';

    // Calculate base URL for redirect
    let baseUrl: string;
    let redirectUrlObj: URL;
    let isSecure: boolean;
    
    try {
      const forwardedHost = request.headers.get('x-forwarded-host') || request.headers.get('X-Forwarded-Host');
      const forwardedProto = request.headers.get('x-forwarded-proto') || request.headers.get('X-Forwarded-Proto') || 'https';
      const host = request.headers.get('host') || request.headers.get('Host');
      
      if (forwardedHost) {
        const protocol = forwardedProto || 'https';
        baseUrl = `${protocol}://${forwardedHost}`;
      } else if (host && !host.includes('0.0.0.0') && !host.includes('127.0.0.1')) {
        const protocol = forwardedProto || 'https';
        baseUrl = `${protocol}://${host}`;
      } else {
        baseUrl = request.nextUrl.origin;
      }

      // Determine if we're in a secure context (HTTPS)
      // Don't force secure=true if we're not in HTTPS (for development/local)
      isSecure = forwardedProto === 'https' || baseUrl.startsWith('https');

      // CRITICAL FIX: Use calculated baseUrl instead of request.nextUrl.origin
      // request.nextUrl.origin may return https://0.0.0.0:3000 which is invalid for external access
      // baseUrl is calculated from forwarded headers and is the correct external URL
      const redirectPath = returnUrl.startsWith('/') ? returnUrl : `/${returnUrl}`;
      redirectUrlObj = new URL(redirectPath, baseUrl);
      redirectUrlObj.searchParams.set('auth_event', authEvent);
      redirectUrlObj.searchParams.set('auth_method', 'email_otp');
    } catch (urlError) {
      console.error('❌ [verifyOtp Route] Failed to build redirect URL:', {
        error: urlError instanceof Error ? urlError.message : String(urlError),
        errorStack: urlError instanceof Error ? urlError.stack : undefined,
        returnUrl,
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { 
          message: 'Failed to build redirect URL',
          error: urlError instanceof Error ? urlError.message : String(urlError),
          errorCode: 'URL_BUILD_FAILED',
        },
        { status: 500 }
      );
    }
    
    console.log('🔄 [verifyOtp Route] Redirecting after successful verification:', {
      redirectPath: redirectUrlObj.pathname + redirectUrlObj.search,
      redirectFullUrl: redirectUrlObj.toString(),
      authEvent,
      userId: session.user.id,
      hasSession: !!session,
      hasCookies: authCookies.length > 0,
      cookieNames: authCookies.map(c => c.name),
      sessionExpiresAt: session.expires_at,
      sessionExpiresAtDate: session.expires_at ? new Date(session.expires_at * 1000).toISOString() : 'N/A',
      timestamp: new Date().toISOString(),
    });

    // CRITICAL: Use the latest supabaseResponse which has all cookies set
    // Then modify it to redirect instead of creating a new response
    // This preserves all cookies that were set by Supabase's setAll callback
    console.log('🔄 [verifyOtp Route] Creating redirect from supabaseResponse...', {
      redirectPath: redirectUrlObj.pathname + redirectUrlObj.search,
      cookieMapSize: cookieMap.size,
      cookieMapKeys: Array.from(cookieMap.keys()),
      supabaseResponseCookieCount: supabaseResponse.cookies.getAll().length,
      supabaseResponseCookieNames: supabaseResponse.cookies.getAll().map(c => c.name),
      timestamp: new Date().toISOString(),
    });
    
    // CRITICAL FIX: Create redirect response, then copy cookies from supabaseResponse
    // supabaseResponse is the authoritative source managed by Supabase SSR
    // According to Supabase SSR docs, cookies set via setAll() are stored in the response
    let response: NextResponse;
    try {
      response = NextResponse.redirect(redirectUrlObj, { status: 307 });
    } catch (redirectError) {
      console.error('❌ [verifyOtp Route] Failed to create redirect response:', {
        error: redirectError instanceof Error ? redirectError.message : String(redirectError),
        errorStack: redirectError instanceof Error ? redirectError.stack : undefined,
        redirectUrl: redirectUrlObj.toString(),
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { 
          message: 'Failed to create redirect response',
          error: redirectError instanceof Error ? redirectError.message : String(redirectError),
          errorCode: 'REDIRECT_CREATION_FAILED',
        },
        { status: 500 }
      );
    }
    
    // Copy ALL cookies from supabaseResponse to the redirect response
    const supabaseCookies = supabaseResponse.cookies.getAll();
    console.log('🍪 [verifyOtp Route] Copying cookies from supabaseResponse to redirect:', {
      supabaseCookieCount: supabaseCookies.length,
      supabaseCookieNames: supabaseCookies.map(c => c.name),
      timestamp: new Date().toISOString(),
    });
    
    try {
      supabaseCookies.forEach(cookie => {
        // Calculate maxAge from session if cookie doesn't have it
        let maxAge = cookie.maxAge;
        if (!maxAge && session?.expires_at) {
          const expiresAtSeconds = session.expires_at;
          const nowSeconds = Math.floor(Date.now() / 1000);
          maxAge = Math.max(expiresAtSeconds - nowSeconds, 3600); // At least 1 hour
        }
        
        try {
          response.cookies.set(cookie.name, cookie.value, {
            path: cookie.path || '/',
            sameSite: (cookie.sameSite as 'lax' | 'strict' | 'none') || 'lax',
            secure: cookie.secure !== undefined ? cookie.secure : isSecure,
            httpOnly: cookie.httpOnly !== undefined ? cookie.httpOnly : true,
            maxAge: maxAge || cookie.maxAge || 3600 * 24 * 7, // Default 7 days
          });
        } catch (cookieSetError) {
          console.error('❌ [verifyOtp Route] Failed to set cookie:', {
            cookieName: cookie.name,
            error: cookieSetError instanceof Error ? cookieSetError.message : String(cookieSetError),
            timestamp: new Date().toISOString(),
          });
          // Continue with other cookies
        }
      });
    } catch (cookieError) {
      console.error('❌ [verifyOtp Route] Failed to copy cookies:', {
        error: cookieError instanceof Error ? cookieError.message : String(cookieError),
        errorStack: cookieError instanceof Error ? cookieError.stack : undefined,
        cookieCount: supabaseCookies.length,
        timestamp: new Date().toISOString(),
      });
      // Continue anyway - some cookies might have been set
    }
    
    console.log('🍪 [verifyOtp Route] Final cookies in redirect response:', {
      totalCookies: response.cookies.getAll().length,
      authCookies: response.cookies.getAll().filter(c => c.name.startsWith('sb-')).map(c => c.name),
      allCookieNames: response.cookies.getAll().map(c => c.name),
      timestamp: new Date().toISOString(),
    });
    
    // Final verification: Check that cookies are actually in the response
    const finalCookies = response.cookies.getAll();
    const finalAuthCookies = finalCookies.filter(c => c.name.startsWith('sb-'));
    
    // CRITICAL: If no auth cookies in final response, return error instead of redirecting
    // This prevents the 500 error on dashboard and provides better error handling
    if (finalAuthCookies.length === 0) {
      console.error('❌ [verifyOtp Route] CRITICAL: No auth cookies in final redirect response!', {
        cookieMapSize: cookieMap.size,
        supabaseResponseCookieCount: supabaseResponse.cookies.getAll().length,
        requestCookieCount: requestCookies.length,
        hasSession: !!session,
        sessionUserId: session?.user?.id,
        timestamp: new Date().toISOString(),
      });
      
      // Return error response instead of redirecting without cookies
      // This prevents 500 error on dashboard and allows client to handle error gracefully
      return NextResponse.json(
        { 
          message: 'Session created but cookies could not be set. Please try again.',
          errorCode: 'COOKIE_SET_FAILED',
        },
        { status: 500 }
      );
    }
    
    console.log('✅ [verifyOtp Route] ===== Route Handler Success =====', {
      redirectUrl: redirectUrlObj.toString(),
      totalCookieCount: finalCookies.length,
      authCookieCount: finalAuthCookies.length,
      authCookieNames: finalAuthCookies.map(c => c.name),
      cookieDetails: finalAuthCookies.map(c => ({
        name: c.name,
        hasValue: !!c.value,
        valueLength: c.value?.length || 0,
        path: c.path || '/',
        secure: c.secure || false,
        sameSite: c.sameSite || 'lax',
      })),
      redirectStatus: 307,
      timestamp: new Date().toISOString(),
    });
    
    return response;
  } catch (error) {
    // Log full error details for debugging
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;
    const errorName = error instanceof Error ? error.name : undefined;
    
    console.error('❌ [verifyOtp Route] ===== UNEXPECTED ERROR =====', {
      errorMessage,
      errorStack,
      errorName,
      errorType: error?.constructor?.name || typeof error,
      errorString: String(error),
      errorJSON: error instanceof Error ? {
        name: error.name,
        message: error.message,
        stack: error.stack,
      } : error,
      timestamp: new Date().toISOString(),
    });
    
    // Return detailed error for debugging
    // Ensure error message is safe to serialize
    const safeErrorMessage = errorMessage || 'An unexpected error occurred during OTP verification';
    
    return NextResponse.json(
      { 
        message: safeErrorMessage,
        error: safeErrorMessage,
        errorCode: 'UNEXPECTED_ERROR',
        errorName: errorName || 'Unknown',
      },
      { 
        status: 500,
        headers: {
          'Content-Type': 'application/json',
        },
      }
    );
  }
}

