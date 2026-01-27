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
  console.log('🔍 Auth callback route hit:', {
    url: request.url,
    pathname: request.nextUrl.pathname,
    searchParams: Object.fromEntries(request.nextUrl.searchParams),
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
  const protocol = request.headers.get('x-forwarded-proto') || request.nextUrl.protocol;
  
  let baseUrl: string;
  if (forwardedHost) {
    baseUrl = `${protocol}//${forwardedHost}`;
  } else if (host) {
    baseUrl = `${protocol}//${host}`;
  } else {
    baseUrl = request.nextUrl.origin || process.env.NEXT_PUBLIC_URL || 'http://localhost:3000';
  }
  
  console.log('🌐 Base URL determined:', {
    forwardedHost,
    host,
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

  // Handle token-based verification (magic link PKCE token)
  // Supabase sends these to the redirect URL for processing
  if (token) {
    // Default to 'magiclink' if type is not provided (for PKCE tokens)
    const finalType = type || 'magiclink';
    
    console.log('🔍 Callback route processing token:', {
      token: token.substring(0, 20) + '...',
      type: finalType,
      hasReturnUrl: !!next,
    });

    try {
      // For PKCE magic link tokens, Supabase may return them as "code" in the URL
      // But sometimes they come as "token" parameter
      // Try exchangeCodeForSession first (most common for PKCE flow)
      // If that fails, fall back to verifyOtp
      
      let data: any = null;
      let error: any = null;
      
      // First, try exchangeCodeForSession (for PKCE flow)
      // This is the standard method for PKCE magic link tokens
      console.log('🔄 Trying exchangeCodeForSession for PKCE token...');
      const exchangeResult = await supabase.auth.exchangeCodeForSession(token);
      
      if (exchangeResult.error) {
        console.log('⚠️ exchangeCodeForSession failed, trying verifyOtp with token_hash:', exchangeResult.error.message);
        
        // Fall back to verifyOtp with token_hash
        // For PKCE tokens, we use token_hash (not token + email)
        const verifyResult = await supabase.auth.verifyOtp({
          token_hash: token,
          type: finalType as any,
        });
        
        if (verifyResult.error) {
          // Both methods failed - this token format is not supported
          error = verifyResult.error;
          console.error('❌ All verification methods failed:', {
            exchangeError: exchangeResult.error.message,
            verifyError: verifyResult.error.message,
            tokenPrefix: token.substring(0, 20),
            type: finalType,
          });
        } else {
          data = verifyResult.data;
          console.log('✅ verifyOtp with token_hash succeeded');
        }
      } else {
        data = exchangeResult.data;
        console.log('✅ exchangeCodeForSession succeeded');
      }

      if (error) {
        console.error('❌ Error verifying token:', error)
        
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

          console.log('🔄 Token expired, redirecting to auth page with expired state')
          return NextResponse.redirect(expiredUrl)
        }
        
        return NextResponse.redirect(`${baseUrl}/auth?error=${encodeURIComponent(error.message)}`)
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

        // Ensure session is properly established by getting it
        // This ensures cookies are set correctly via createServerClient's setAll
        const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
        
        if (sessionError) {
          console.error('❌ Error getting session after token verification:', sessionError);
        } else {
          console.log('✅ Session established:', {
            hasSession: !!sessionData.session,
            userId: sessionData.session?.user?.id,
          });
        }

        // Redirect to dashboard with auth tracking params
        const redirectUrl = new URL(`${baseUrl}${next}`)
        redirectUrl.searchParams.set('auth_event', authEvent)
        redirectUrl.searchParams.set('auth_method', authMethod)
        
        // Create redirect response
        // The cookies should already be set by createServerClient's setAll method via cookieStore.set()
        // In Next.js App Router, cookies set via cookies().set() are automatically included in responses
        const redirectResponse = NextResponse.redirect(redirectUrl)
        
        // Explicitly ensure cookies are included by reading from cookie store
        // This is a safety measure to ensure cookies are in the redirect response
        const { cookies } = await import('next/headers');
        const cookieStore = await cookies();
        const allCookies = cookieStore.getAll();
        
        // Log cookie information for debugging
        console.log('✅ Token verified successfully, redirecting to:', redirectUrl.toString(), {
          cookiesCount: allCookies.length,
          cookieNames: allCookies.map(c => c.name).filter(name => name.includes('supabase') || name.includes('auth')),
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
