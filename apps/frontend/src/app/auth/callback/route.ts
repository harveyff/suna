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
  const { searchParams } = new URL(request.url)
  const code = searchParams.get('code')
  const token = searchParams.get('token') // Supabase verification token
  const type = searchParams.get('type') // signup, recovery, etc.
  const redirectTo = searchParams.get('redirect_to') // May contain email in URL params
  const next = searchParams.get('returnUrl') || searchParams.get('redirect') || '/dashboard'
  const termsAccepted = searchParams.get('terms_accepted') === 'true'
  
  // Extract email from various sources
  let email = searchParams.get('email') || '' // Email passed from magic link redirect URL
  if (!email && redirectTo) {
    // Try to extract email from redirect_to URL
    try {
      const redirectToUrl = new URL(redirectTo);
      email = redirectToUrl.searchParams.get('email') || email;
    } catch (e) {
      // Ignore URL parsing errors
    }
  }

  // Calculate base URL from request headers (handles proxy environments)
  // Priority: X-Forwarded-Host + X-Forwarded-Proto > request.nextUrl.origin > env var
  const forwardedHost = request.headers.get('x-forwarded-host') || request.headers.get('X-Forwarded-Host');
  const forwardedProto = request.headers.get('x-forwarded-proto') || request.headers.get('X-Forwarded-Proto') || 'https';
  const host = request.headers.get('host') || request.headers.get('Host');
  
  let baseUrl: string;
  if (forwardedHost) {
    // Use forwarded host (most reliable in proxy environments)
    const protocol = forwardedProto || 'https';
    baseUrl = `${protocol}://${forwardedHost}`;
  } else if (host && !host.includes('0.0.0.0') && !host.includes('127.0.0.1')) {
    // Use Host header if it's not localhost/0.0.0.0
    const protocol = forwardedProto || (request.nextUrl.protocol || 'https');
    baseUrl = `${protocol}://${host}`;
  } else if (request.nextUrl.origin && !request.nextUrl.origin.includes('0.0.0.0')) {
    // Use request origin if it's not 0.0.0.0
    baseUrl = request.nextUrl.origin;
  } else {
    // Fallback to env var or default
    baseUrl = process.env.NEXT_PUBLIC_URL || 'http://localhost:3000';
  }
  
  // Log base URL calculation for debugging
  console.log('🔍 [AUTH_CALLBACK] Base URL calculation:', {
    forwardedHost,
    forwardedProto,
    host,
    requestOrigin: request.nextUrl.origin,
    calculatedBaseUrl: baseUrl,
    envUrl: process.env.NEXT_PUBLIC_URL,
    timestamp: new Date().toISOString(),
  });
  const error = searchParams.get('error')
  const errorCode = searchParams.get('error_code')
  const errorDescription = searchParams.get('error_description')

  // Log request details for debugging
  console.log('🔍 [AUTH_CALLBACK] Route handler started:', {
    url: request.url,
    pathname: request.nextUrl.pathname,
    searchParams: Object.fromEntries(searchParams),
    method: request.method,
    headers: {
      host: request.headers.get('host'),
      'x-forwarded-host': request.headers.get('x-forwarded-host'),
      'x-forwarded-proto': request.headers.get('x-forwarded-proto'),
      'x-forwarded-for': request.headers.get('x-forwarded-for'),
    },
    hasCode: !!code,
    hasToken: !!token,
    hasType: !!type,
    tokenPreview: token ? token.substring(0, 20) + '...' : null,
    type,
    email,
    returnUrl: next,
    baseUrl,
    timestamp: new Date().toISOString(),
  });


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

  // Handle token-based verification (PKCE magic links, email confirmation, etc.)
  // PKCE tokens start with "pkce_" and should be treated as codes for exchangeCodeForSession
  if (token && type) {
    console.log('🔍 [AUTH_CALLBACK] Processing token-based verification:', {
      tokenPreview: token.substring(0, 20) + '...',
      type,
      isPkceToken: token.startsWith('pkce_'),
      email,
      returnUrl: next,
      timestamp: new Date().toISOString(),
    });

    // PKCE tokens (magic links) - try exchangeCodeForSession first, then fallback to verifyOtp
    if (token.startsWith('pkce_')) {
      try {
        // First, try to use the token as a code for exchangeCodeForSession
        // Remove "pkce_" prefix if present
        const codeValue = token.replace(/^pkce_/, '');
        console.log('🔍 [AUTH_CALLBACK] Attempting exchangeCodeForSession with PKCE token:', {
          tokenPreview: token.substring(0, 20) + '...',
          codeValuePreview: codeValue.substring(0, 20) + '...',
          hasEmail: !!email,
          timestamp: new Date().toISOString(),
        });
        
        const { data, error } = await supabase.auth.exchangeCodeForSession(codeValue);
        
        if (error) {
          console.warn('⚠️ [AUTH_CALLBACK] exchangeCodeForSession failed, trying verifyOtp:', {
            error: error.message,
            errorCode: error.code,
            errorStatus: error.status,
            hasEmail: !!email,
            timestamp: new Date().toISOString(),
          });
          
          // If exchangeCodeForSession fails and we have email, try verifyOtp
          // But verifyOtp requires a 6-digit code, not a PKCE token
          // So we'll redirect to auth page for manual OTP entry
          if (error.code === 'flow_state_not_found' && email) {
            const authUrl = new URL(`${baseUrl}/auth`, baseUrl);
            authUrl.searchParams.set('token', token);
            authUrl.searchParams.set('type', type);
            authUrl.searchParams.set('email', email);
            authUrl.searchParams.set('returnUrl', next);
            if (termsAccepted) authUrl.searchParams.set('terms_accepted', 'true');
            console.log('🔄 [AUTH_CALLBACK] Redirecting to auth page for OTP entry:', {
              authUrl: authUrl.toString(),
              timestamp: new Date().toISOString(),
            });
            return NextResponse.redirect(authUrl);
          }
          
          // Check if expired/invalid
          const isExpired = 
            error.message?.toLowerCase().includes('expired') ||
            error.message?.toLowerCase().includes('invalid') ||
            error.status === 400 ||
            error.code === 'expired_token' ||
            error.code === 'token_expired' ||
            error.code === 'otp_expired';
          
          if (isExpired) {
            const expiredUrl = new URL(`${baseUrl}/auth`, baseUrl);
            expiredUrl.searchParams.set('expired', 'true');
            if (email) expiredUrl.searchParams.set('email', email);
            if (next) expiredUrl.searchParams.set('returnUrl', next);
            console.log('🔄 [AUTH_CALLBACK] Redirecting to auth page with expired state');
            return NextResponse.redirect(expiredUrl);
          }
          
          return NextResponse.redirect(`${baseUrl}/auth?error=${encodeURIComponent(error.message)}`);
        }

        // Success - redirect to dashboard
        if (data?.user) {
          const redirectUrl = new URL(`${baseUrl}${next}`, baseUrl);
          redirectUrl.searchParams.set('auth_event', 'login');
          redirectUrl.searchParams.set('auth_method', 'email');
          console.log('✅ [AUTH_CALLBACK] PKCE token verified successfully via exchangeCodeForSession, redirecting:', {
            redirectUrl: redirectUrl.toString(),
            userId: data.user.id,
            timestamp: new Date().toISOString(),
          });
          return NextResponse.redirect(redirectUrl);
        }
      } catch (err) {
        console.error('❌ [AUTH_CALLBACK] Exception processing PKCE token:', err);
        return NextResponse.redirect(`${baseUrl}/auth?error=unexpected_error`);
      }
    } else {
      // For non-PKCE tokens, redirect to auth page for client-side handling
      const verifyUrl = new URL(`${baseUrl}/auth`, request.url);
      verifyUrl.searchParams.set('token', token);
      verifyUrl.searchParams.set('type', type);
      if (termsAccepted) verifyUrl.searchParams.set('terms_accepted', 'true');
      if (email) verifyUrl.searchParams.set('email', email);
      if (next) verifyUrl.searchParams.set('returnUrl', next);
      
      console.log('🔄 [AUTH_CALLBACK] Redirecting non-PKCE token to auth page:', {
        verifyUrl: verifyUrl.toString(),
        timestamp: new Date().toISOString(),
      });
      return NextResponse.redirect(verifyUrl);
    }
  }

  // Handle code exchange (OAuth, magic link)
  if (code) {
    try {
      const { data, error } = await supabase.auth.exchangeCodeForSession(code)
      
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

      return response
    } catch (error) {
      console.error('❌ Unexpected error in auth callback:', error)
      return NextResponse.redirect(`${baseUrl}/auth?error=unexpected_error`)
    }
  }
  
  // No code or token - redirect to auth page
  return NextResponse.redirect(`${baseUrl}/auth`)
}
