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
  const { searchParams } = new URL(request.url)
  const code = searchParams.get('code')
  const token = searchParams.get('token') // Supabase verification token
  const type = searchParams.get('type') // signup, recovery, etc.
  const next = searchParams.get('returnUrl') || searchParams.get('redirect') || '/dashboard'
  const termsAccepted = searchParams.get('terms_accepted') === 'true'
  const email = searchParams.get('email') || '' // Email passed from magic link redirect URL

  // Calculate correct base URL from headers (handles proxy environments)
  // This ensures we use the external URL, not internal 0.0.0.0:3000
  const forwardedHost = request.headers.get('x-forwarded-host') || request.headers.get('X-Forwarded-Host')
  const forwardedProto = request.headers.get('x-forwarded-proto') || request.headers.get('X-Forwarded-Proto') || 'https'
  const host = request.headers.get('host') || request.headers.get('Host')
  
  let baseUrl: string
  if (forwardedHost) {
    const protocol = forwardedProto || 'https'
    baseUrl = `${protocol}://${forwardedHost}`
  } else if (host && !host.includes('0.0.0.0') && !host.includes('127.0.0.1')) {
    const protocol = forwardedProto || 'https'
    baseUrl = `${protocol}://${host}`
  } else {
    baseUrl = request.nextUrl.origin || process.env.NEXT_PUBLIC_URL || 'http://localhost:3000'
  }
  const error = searchParams.get('error')
  const errorCode = searchParams.get('error_code')
  const errorDescription = searchParams.get('error_description')


  // Handle errors FIRST - before any Supabase operations that might affect session
  if (error) {
    console.error('❌ Auth callback error:', error, errorCode, errorDescription)

    // Check if the error is due to expired/invalid link
    // Only check explicit error codes, not generic error messages
    const isExpiredOrInvalid =
      errorCode === 'otp_expired' ||
      errorCode === 'expired_token' ||
      errorCode === 'token_expired' ||
      (errorCode === 'invalid_grant' && (errorDescription?.toLowerCase().includes('expired') || error?.toLowerCase().includes('expired')))

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

  // Note: We don't skip token processing even if user is already authenticated
  // because the token might be invalid/expired, and we need to show OTP input page
  // The token processing logic below will handle this correctly

  // Handle token-based verification (email confirmation, PKCE magic links, etc.)
  // Supabase sends these to the redirect URL for processing
  if (token && type) {
    // Extract email from redirect_to parameter if available
    const redirectTo = searchParams.get('redirect_to') || ''
    let extractedEmail = email
    if (!extractedEmail && redirectTo) {
      try {
        const redirectUrl = new URL(redirectTo)
        extractedEmail = redirectUrl.searchParams.get('email') || ''
      } catch (e) {
        // redirect_to might not be a valid URL, try parsing as query string
        const match = redirectTo.match(/email=([^&]+)/)
        if (match) {
          extractedEmail = decodeURIComponent(match[1])
        }
      }
    }

    // Handle PKCE magic link tokens (prefixed with pkce_)
    if (token.startsWith('pkce_')) {
      console.log('🔐 [AUTH_CALLBACK] Processing PKCE token:', {
        tokenPrefix: token.substring(0, 20) + '...',
        tokenLength: token.length,
        hasEmail: !!extractedEmail,
        email: extractedEmail,
        type,
        redirectTo: redirectTo || 'N/A',
        timestamp: new Date().toISOString(),
      });
      
      try {
        // Remove pkce_ prefix and try to exchange for session
        const codeWithoutPrefix = token.replace(/^pkce_/, '')
        console.log('🔄 [AUTH_CALLBACK] Attempting exchangeCodeForSession:', {
          codeLength: codeWithoutPrefix.length,
          codePrefix: codeWithoutPrefix.substring(0, 20) + '...',
          timestamp: new Date().toISOString(),
        });
        
        const { data, error } = await supabase.auth.exchangeCodeForSession(codeWithoutPrefix)
        
        if (error) {
          console.error('❌ [AUTH_CALLBACK] PKCE token verification failed:', {
            error: error.message,
            errorCode: error.code,
            errorStatus: error.status,
            tokenPrefix: token.substring(0, 20) + '...',
            hasEmail: !!extractedEmail,
            email: extractedEmail,
            timestamp: new Date().toISOString(),
          });
          
          // Handle flow_state_not_found separately - it's not necessarily expired, just needs OTP entry
          // This allows users to enter OTP code even if PKCE flow state is lost
          if (error.code === 'flow_state_not_found' && extractedEmail) {
            console.log('🔄 [AUTH_CALLBACK] PKCE flow state not found, redirecting to /auth for OTP entry:', {
              email: extractedEmail,
              errorCode: error.code,
              errorMessage: error.message,
              returnUrl: next,
              timestamp: new Date().toISOString(),
            });
            
            const authUrl = new URL(`${baseUrl}/auth`)
            authUrl.searchParams.set('email', extractedEmail)
            authUrl.searchParams.set('expired', 'true')
            authUrl.searchParams.set('pkce_expired', 'true') // Flag to skip "link expired" message
            if (next) authUrl.searchParams.set('returnUrl', next)
            
            console.log('🔄 [AUTH_CALLBACK] Redirecting to auth page:', {
              redirectUrl: authUrl.toString(),
              email: extractedEmail,
              timestamp: new Date().toISOString(),
            });
            
            return NextResponse.redirect(authUrl)
          }
          
          // Check if expired/invalid - only mark as expired if explicitly stated in error code
          const isExpired = 
            error.code === 'expired_token' ||
            error.code === 'token_expired' ||
            error.code === 'otp_expired' ||
            (error.code === 'invalid_grant' && error.message?.toLowerCase().includes('expired'))
          
          if (isExpired) {
            // Redirect to auth page with expired state
            const expiredUrl = new URL(`${baseUrl}/auth`)
            expiredUrl.searchParams.set('expired', 'true')
            if (extractedEmail) expiredUrl.searchParams.set('email', extractedEmail)
            if (next) expiredUrl.searchParams.set('returnUrl', next)
            return NextResponse.redirect(expiredUrl)
          }
          
          // For other errors, redirect to auth page with error (but don't mark as expired)
          const errorUrl = new URL(`${baseUrl}/auth`)
          errorUrl.searchParams.set('error', error.message || 'verification_failed')
          if (extractedEmail) errorUrl.searchParams.set('email', extractedEmail)
          if (next) errorUrl.searchParams.set('returnUrl', next)
          return NextResponse.redirect(errorUrl)
        }
        
        // Success - user is authenticated
        if (data.user) {
          console.log('✅ [AUTH_CALLBACK] PKCE token verified successfully:', {
            userId: data.user.id,
            email: data.user.email,
            hasSession: !!data.session,
            sessionExpiresAt: data.session?.expires_at,
            timestamp: new Date().toISOString(),
          });
          
          // Handle terms acceptance if needed
          if (termsAccepted) {
            const currentMetadata = data.user.user_metadata || {}
            if (!currentMetadata.terms_accepted_at) {
              try {
                await supabase.auth.updateUser({
                  data: {
                    ...currentMetadata,
                    terms_accepted_at: new Date().toISOString(),
                  },
                })
                console.log('✅ Terms acceptance date saved to user metadata')
              } catch (updateError) {
                console.warn('⚠️ Failed to save terms acceptance:', updateError)
              }
            }
          }
          
          // Redirect to dashboard or returnUrl
          const redirectUrl = new URL(`${baseUrl}${next}`)
          redirectUrl.searchParams.set('auth_event', 'login')
          redirectUrl.searchParams.set('auth_method', 'email')
          return NextResponse.redirect(redirectUrl)
        }
      } catch (error) {
        console.error('❌ Unexpected error processing PKCE token:', error)
        const errorUrl = new URL(`${baseUrl}/auth`)
        errorUrl.searchParams.set('error', 'unexpected_error')
        if (extractedEmail) errorUrl.searchParams.set('email', extractedEmail)
        return NextResponse.redirect(errorUrl)
      }
    }
    
    // For other token-based flows, redirect to auth page that can handle the verification client-side
    const verifyUrl = new URL(`${baseUrl}/auth`)
    verifyUrl.searchParams.set('token', token)
    verifyUrl.searchParams.set('type', type)
    if (termsAccepted) verifyUrl.searchParams.set('terms_accepted', 'true')
    if (extractedEmail) verifyUrl.searchParams.set('email', extractedEmail)
    
    return NextResponse.redirect(verifyUrl)
  }

  // Handle code exchange (OAuth, magic link)
  if (code) {
    try {
      const { data, error } = await supabase.auth.exchangeCodeForSession(code)
      
      if (error) {
        console.error('❌ Error exchanging code for session:', error)
        
        // Check if the error is due to expired/invalid link
        // Only check explicit error codes, not generic error messages or status codes
        const isExpired = 
          error.code === 'expired_token' ||
          error.code === 'token_expired' ||
          error.code === 'otp_expired' ||
          (error.code === 'invalid_grant' && error.message?.toLowerCase().includes('expired'))
        
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
