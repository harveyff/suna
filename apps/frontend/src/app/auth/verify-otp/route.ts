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
    const formData = await request.formData();
    const email = formData.get('email') as string;
    const token = formData.get('token') as string;
    const returnUrl = (formData.get('returnUrl') as string) || '/dashboard';

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

    if (!token || token.length !== 6) {
      return NextResponse.json(
        { message: 'Please enter the 6-digit code from your email' },
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
            cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
            supabaseResponse = NextResponse.next({
              request,
            });
            cookiesToSet.forEach(({ name, value, options }) =>
              supabaseResponse.cookies.set(name, value, options)
            );
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
    const normalizedToken = token.trim();
    
    console.log('🔐 [verifyOtp Route] Calling supabase.auth.verifyOtp with type=email...', {
      email: normalizedEmail,
      tokenLength: normalizedToken.length,
      tokenPrefix: normalizedToken.substring(0, 2) + '****',
      type: 'email',
      supabaseUrl: supabaseUrl.substring(0, 50) + '...',
      timestamp: new Date().toISOString(),
    });

    // Try 'email' type first (for 6-digit OTP codes)
    // If that fails with specific error, we might need to try 'magiclink' type
    // But typically 'email' is correct for OTP codes sent via signInWithOtp
    let verifyResult = await supabase.auth.verifyOtp({
      email: normalizedEmail,
      token: normalizedToken,
      type: 'email', // Changed from 'magiclink' to 'email' for 6-digit OTP codes
    });
    
    // If 'email' type fails with "invalid" error, log but don't retry with 'magiclink'
    // because if user received a 6-digit code, it must be 'email' type
    // The error is likely due to expired/invalid code, not wrong type
    console.log('🔐 [verifyOtp Route] verifyOtp response received:', {
      hasData: !!verifyResult.data,
      hasError: !!verifyResult.error,
      errorMessage: verifyResult.error?.message,
      errorCode: verifyResult.error?.code,
      errorStatus: verifyResult.error?.status,
      userId: verifyResult.data?.user?.id,
      hasSession: !!verifyResult.data?.session,
      typeUsed: 'email',
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
        type: 'email',
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
      timestamp: new Date().toISOString(),
    });

    // Verify session is set after OTP verification
    const { data: { session } } = await supabase.auth.getSession();
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

    console.log('✅ [verifyOtp Route] Session created successfully:', {
      userId: session.user.id,
      email: session.user.email,
      expiresAt: session.expires_at,
      expiresAtDate: session.expires_at ? new Date(session.expires_at * 1000).toISOString() : 'N/A',
      timestamp: new Date().toISOString(),
    });

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

    // Determine if new user (for analytics)
    const isNewUser = data.user && (Date.now() - new Date(data.user.created_at).getTime()) < 60000;
    const authEvent = isNewUser ? 'signup' : 'login';

    // Calculate base URL for redirect
    const forwardedHost = request.headers.get('x-forwarded-host') || request.headers.get('X-Forwarded-Host');
    const forwardedProto = request.headers.get('x-forwarded-proto') || request.headers.get('X-Forwarded-Proto') || 'https';
    const host = request.headers.get('host') || request.headers.get('Host');
    
    let baseUrl: string;
    if (forwardedHost) {
      const protocol = forwardedProto || 'https';
      baseUrl = `${protocol}://${forwardedHost}`;
    } else if (host && !host.includes('0.0.0.0') && !host.includes('127.0.0.1')) {
      const protocol = forwardedProto || 'https';
      baseUrl = `${protocol}://${host}`;
    } else {
      baseUrl = request.nextUrl.origin;
    }

    const redirectUrl = new URL(returnUrl, baseUrl);
    redirectUrl.searchParams.set('auth_event', authEvent);
    redirectUrl.searchParams.set('auth_method', 'email_otp');
    
    console.log('🔄 [verifyOtp Route] Redirecting after successful verification:', {
      redirectTo: redirectUrl.toString(),
      authEvent,
      userId: session.user.id,
      hasSession: !!session,
      hasCookies: authCookies.length > 0,
      cookieNames: authCookies.map(c => c.name),
      timestamp: new Date().toISOString(),
    });

    // CRITICAL: Create redirect response and ensure cookies are included
    // The cookies are set by createServerClient via setAll() into supabaseResponse
    // We must copy them to the redirect response to ensure they persist
    console.log('🔄 [verifyOtp Route] Creating redirect response with cookies...', {
      redirectUrl: redirectUrl.toString(),
      supabaseResponseCookieCount: supabaseResponse.cookies.getAll().length,
      supabaseResponseCookieNames: supabaseResponse.cookies.getAll().map(c => c.name),
      forwardedProto,
      isSecure: forwardedProto === 'https',
      timestamp: new Date().toISOString(),
    });
    
    const response = NextResponse.redirect(redirectUrl);
    
    // Copy all cookies from supabaseResponse to the redirect response
    // This ensures cookies are properly set in the redirect response
    // Without this, cookies may not persist after redirect
    const supabaseResponseCookies = supabaseResponse.cookies.getAll();
    console.log('🍪 [verifyOtp Route] Copying cookies to redirect response:', {
      cookieCount: supabaseResponseCookies.length,
      cookieNames: supabaseResponseCookies.map(c => c.name),
      cookieDetails: supabaseResponseCookies.map(c => ({
        name: c.name,
        hasValue: !!c.value,
        valueLength: c.value?.length || 0,
      })),
      timestamp: new Date().toISOString(),
    });
    
    // Determine if we're in a secure context (HTTPS)
    // Don't force secure=true if we're not in HTTPS (for development/local)
    const isSecure = forwardedProto === 'https' || baseUrl.startsWith('https');
    
    supabaseResponseCookies.forEach(cookie => {
      // Use the same options that Supabase uses, but ensure they're compatible
      // Don't force secure=true if we're not in HTTPS (for development)
      response.cookies.set(cookie.name, cookie.value, {
        path: '/',
        sameSite: 'lax',
        secure: isSecure, // Only set secure in HTTPS
        httpOnly: true,
      });
      
      console.log('🍪 [verifyOtp Route] Cookie set in redirect response:', {
        name: cookie.name,
        hasValue: !!cookie.value,
        valueLength: cookie.value?.length || 0,
        secure: isSecure,
        timestamp: new Date().toISOString(),
      });
    });
    
    // Also copy cookies from request.cookies (in case they were set there)
    requestAuthCookies.forEach(cookie => {
      // Only set if not already in response
      if (!supabaseResponseCookies.find(c => c.name === cookie.name)) {
        console.log('🍪 [verifyOtp Route] Adding cookie from request:', {
          name: cookie.name,
          hasValue: !!cookie.value,
          timestamp: new Date().toISOString(),
        });
        response.cookies.set(cookie.name, cookie.value, {
          path: '/',
          sameSite: 'lax',
          secure: isSecure,
          httpOnly: true,
        });
      }
    });
    
    console.log('🍪 [verifyOtp Route] Final cookies in redirect response:', {
      totalCookies: response.cookies.getAll().length,
      authCookies: response.cookies.getAll().filter(c => c.name.startsWith('sb-')).map(c => c.name),
      allCookieNames: response.cookies.getAll().map(c => c.name),
      timestamp: new Date().toISOString(),
    });
    
    console.log('✅ [verifyOtp Route] ===== Route Handler Success =====', {
      redirectUrl: redirectUrl.toString(),
      cookieCount: response.cookies.getAll().length,
      timestamp: new Date().toISOString(),
    });
    
    return response;
  } catch (error) {
    console.error('❌ [verifyOtp Route] Unexpected error:', {
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString(),
    });
    return NextResponse.json(
      { message: 'An unexpected error occurred' },
      { status: 500 }
    );
  }
}

