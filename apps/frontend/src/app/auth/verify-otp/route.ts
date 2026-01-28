import { createServerClient } from '@supabase/ssr';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Route Handler for OTP verification
 * This ensures cookies are properly set before redirect
 */
export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const email = formData.get('email') as string;
    const token = formData.get('token') as string;
    const returnUrl = (formData.get('returnUrl') as string) || '/dashboard';

    console.log('🔐 [verifyOtp Route] Request received:', {
      hasEmail: !!email,
      hasToken: !!token,
      tokenLength: token?.length || 0,
      returnUrl,
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
      returnUrl,
      timestamp: new Date().toISOString(),
    });

    const { data, error } = await supabase.auth.verifyOtp({
      email: email.trim().toLowerCase(),
      token: token.trim(),
      type: 'magiclink',
    });

    if (error) {
      console.error('❌ [verifyOtp Route] OTP verification failed:', {
        error: error.message,
        errorCode: error.code,
        email: email.trim().toLowerCase(),
        timestamp: new Date().toISOString(),
      });
      return NextResponse.json(
        { message: error.message || 'Invalid or expired code' },
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
    const allCookies = request.cookies.getAll();
    const authCookies = allCookies.filter(c => c.name.startsWith('sb-'));
    
    console.log('🍪 [verifyOtp Route] Cookies after session creation:', {
      totalCookies: allCookies.length,
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

    // Create redirect response using the response object that has cookies set
    // The cookies should already be set by createServerClient via setAll()
    const response = NextResponse.redirect(redirectUrl);
    
    // Copy all cookies from supabaseResponse to the redirect response
    // This ensures cookies are properly set in the redirect response
    const supabaseResponseCookies = supabaseResponse.cookies.getAll();
    supabaseResponseCookies.forEach(cookie => {
      response.cookies.set(cookie.name, cookie.value, {
        path: '/',
        sameSite: 'lax',
        secure: true,
        httpOnly: true,
      });
    });
    
    console.log('🍪 [verifyOtp Route] Cookies in redirect response:', {
      totalCookies: response.cookies.getAll().length,
      authCookies: response.cookies.getAll().filter(c => c.name.startsWith('sb-')).map(c => c.name),
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

