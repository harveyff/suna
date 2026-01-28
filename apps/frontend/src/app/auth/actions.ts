'use server';

import { createTrialCheckout } from '@/lib/api/billing';
import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';


export async function signIn(prevState: any, formData: FormData) {
  const email = formData.get('email') as string;
  const returnUrl = formData.get('returnUrl') as string | undefined;
  const origin = formData.get('origin') as string;
  const acceptedTerms = formData.get('acceptedTerms') === 'true';
  const isDesktopApp = formData.get('isDesktopApp') === 'true';

  if (!email || !email.includes('@')) {
    return { message: 'Please enter a valid email address' };
  }

  const supabase = await createClient();
  const normalizedEmail = email.trim().toLowerCase();

  // Use magic link (passwordless) authentication
  // For desktop app, use custom protocol (kortix://auth/callback) - same as mobile
  // For web, use standard origin (https://kortix.com/auth/callback)
  // Include email in redirect URL so it's available if the link expires
  let emailRedirectTo: string;
  if (isDesktopApp && origin.startsWith('kortix://')) {
    // Match mobile implementation - simple protocol URL with optional terms_accepted
    const params = new URLSearchParams();
    if (acceptedTerms) {
      params.set('terms_accepted', 'true');
    }
    emailRedirectTo = `kortix://auth/callback${params.toString() ? `?${params.toString()}` : ''}`;
  } else {
    emailRedirectTo = `${origin}/auth/callback?returnUrl=${encodeURIComponent(returnUrl || '/dashboard')}&email=${encodeURIComponent(normalizedEmail)}${acceptedTerms ? '&terms_accepted=true' : ''}`;
  }

  const { error } = await supabase.auth.signInWithOtp({
    email: normalizedEmail,
    options: {
      emailRedirectTo,
      shouldCreateUser: true, // Auto-create account if doesn't exist
    },
  });

  if (error) {
    return { message: error.message || 'Could not send magic link' };
  }

  // Return success message - user needs to check email
  return {
    success: true,
    message: 'Check your email for a magic link to sign in',
    email: email.trim().toLowerCase(),
  };
}

export async function signUp(prevState: any, formData: FormData) {
  const origin = formData.get('origin') as string;
  const email = formData.get('email') as string;
  const returnUrl = formData.get('returnUrl') as string | undefined;
  const acceptedTerms = formData.get('acceptedTerms') === 'true';
  const referralCode = formData.get('referralCode') as string | undefined;
  const isDesktopApp = formData.get('isDesktopApp') === 'true';

  if (!email || !email.includes('@')) {
    return { message: 'Please enter a valid email address' };
  }

  if (!acceptedTerms) {
    return { message: 'Please accept the terms and conditions' };
  }

  const supabase = await createClient();
  const normalizedEmail = email.trim().toLowerCase();

  // Use magic link (passwordless) authentication - auto-creates account
  // For desktop app, use custom protocol (kortix://auth/callback) - same as mobile
  // For web, use standard origin (https://kortix.com/auth/callback)
  // Include email in redirect URL so it's available if the link expires
  let emailRedirectTo: string;
  if (isDesktopApp && origin.startsWith('kortix://')) {
    // Match mobile implementation - simple protocol URL with optional terms_accepted
    const params = new URLSearchParams();
    if (acceptedTerms) {
      params.set('terms_accepted', 'true');
    }
    emailRedirectTo = `kortix://auth/callback${params.toString() ? `?${params.toString()}` : ''}`;
  } else {
    emailRedirectTo = `${origin}/auth/callback?returnUrl=${encodeURIComponent(returnUrl || '/dashboard')}&email=${encodeURIComponent(normalizedEmail)}${acceptedTerms ? '&terms_accepted=true' : ''}`;
  }

  const { error } = await supabase.auth.signInWithOtp({
    email: normalizedEmail,
    options: {
      emailRedirectTo,
      shouldCreateUser: true,
      data: referralCode ? {
        referral_code: referralCode.trim().toUpperCase(),
      } : undefined,
    },
  });

  if (error) {
    return { message: error.message || 'Could not send magic link' };
  }

  // Return success message - user needs to check email
  return {
    success: true,
    message: 'Check your email for a magic link to complete sign up',
    email: email.trim().toLowerCase(),
  };
}

export async function forgotPassword(prevState: any, formData: FormData) {
  const email = formData.get('email') as string;
  const origin = formData.get('origin') as string;

  if (!email || !email.includes('@')) {
    return { message: 'Please enter a valid email address' };
  }

  const supabase = await createClient();

  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${origin}/auth/reset-password`,
  });

  if (error) {
    return { message: error.message || 'Could not send password reset email' };
  }

  return {
    success: true,
    message: 'Check your email for a password reset link',
  };
}

export async function resetPassword(prevState: any, formData: FormData) {
  const password = formData.get('password') as string;
  const confirmPassword = formData.get('confirmPassword') as string;

  if (!password || password.length < 6) {
    return { message: 'Password must be at least 6 characters' };
  }

  if (password !== confirmPassword) {
    return { message: 'Passwords do not match' };
  }

  const supabase = await createClient();

  const { error } = await supabase.auth.updateUser({
    password,
  });

  if (error) {
    return { message: error.message || 'Could not update password' };
  }

  return {
    success: true,
    message: 'Password updated successfully',
  };
}

export async function resendMagicLink(prevState: any, formData: FormData) {
  const email = formData.get('email') as string;
  const returnUrl = formData.get('returnUrl') as string | undefined;
  const origin = formData.get('origin') as string;
  const acceptedTerms = formData.get('acceptedTerms') === 'true';
  const isDesktopApp = formData.get('isDesktopApp') === 'true';

  if (!email || !email.includes('@')) {
    return { message: 'Please enter a valid email address' };
  }

  const supabase = await createClient();
  const normalizedEmail = email.trim().toLowerCase();

  // Use magic link (passwordless) authentication
  // For desktop app, use custom protocol (kortix://auth/callback) - same as mobile
  // For web, use standard origin (https://kortix.com/auth/callback)
  // Include email in redirect URL so it's available if the link expires
  let emailRedirectTo: string;
  if (isDesktopApp && origin.startsWith('kortix://')) {
    // Match mobile implementation - simple protocol URL with optional terms_accepted
    const params = new URLSearchParams();
    if (acceptedTerms) {
      params.set('terms_accepted', 'true');
    }
    emailRedirectTo = `kortix://auth/callback${params.toString() ? `?${params.toString()}` : ''}`;
  } else {
    emailRedirectTo = `${origin}/auth/callback?returnUrl=${encodeURIComponent(returnUrl || '/dashboard')}&email=${encodeURIComponent(normalizedEmail)}${acceptedTerms ? '&terms_accepted=true' : ''}`;
  }

  const { error } = await supabase.auth.signInWithOtp({
    email: normalizedEmail,
    options: {
      emailRedirectTo,
      shouldCreateUser: true, // Auto-create account if doesn't exist
    },
  });

  if (error) {
    return { message: error.message || 'Could not send magic link' };
  }

  // Return success message - user needs to check email
  return {
    success: true,
    message: 'Check your email for a magic link to sign in',
    email: email.trim().toLowerCase(),
  };
}

export async function signInWithPassword(prevState: any, formData: FormData) {
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;
  const returnUrl = formData.get('returnUrl') as string | undefined;

  if (!email || !email.includes('@')) {
    return { message: 'Please enter a valid email address' };
  }

  if (!password || password.length < 6) {
    return { message: 'Password must be at least 6 characters' };
  }

  const supabase = await createClient();

  const { data, error } = await supabase.auth.signInWithPassword({
    email: email.trim().toLowerCase(),
    password,
  });

  if (error) {
    return { message: error.message || 'Invalid email or password' };
  }

  // Determine if new user (for analytics)
  const isNewUser = data.user && (Date.now() - new Date(data.user.created_at).getTime()) < 60000;
  const authEvent = isNewUser ? 'signup' : 'login';
  
  // Return success - client will handle redirect with auth tracking params
  const finalReturnUrl = returnUrl || '/dashboard';
  const redirectUrl = new URL(finalReturnUrl, 'http://localhost');
  redirectUrl.searchParams.set('auth_event', authEvent);
  redirectUrl.searchParams.set('auth_method', 'email');
  redirect(`${redirectUrl.pathname}${redirectUrl.search}`);
}

export async function signUpWithPassword(prevState: any, formData: FormData) {
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;
  const confirmPassword = formData.get('confirmPassword') as string;
  const returnUrl = formData.get('returnUrl') as string | undefined;
  const origin = formData.get('origin') as string;

  if (!email || !email.includes('@')) {
    return { message: 'Please enter a valid email address' };
  }

  if (!password || password.length < 6) {
    return { message: 'Password must be at least 6 characters' };
  }

  if (password !== confirmPassword) {
    return { message: 'Passwords do not match' };
  }

  const supabase = await createClient();

  const baseUrl = origin || process.env.NEXT_PUBLIC_URL || 'http://localhost:3000';
  const emailRedirectTo = `${baseUrl}/auth/callback?returnUrl=${encodeURIComponent(returnUrl || '/dashboard')}`;

  const { error } = await supabase.auth.signUp({
    email: email.trim().toLowerCase(),
    password,
    options: {
      emailRedirectTo,
    },
  });

  if (error) {
    return { message: error.message || 'Could not create account' };
  }

  // Return success - client will handle redirect
  const finalReturnUrl = returnUrl || '/dashboard';
  redirect(finalReturnUrl);
}

export async function signOut() {
  const supabase = await createClient();
  const { error } = await supabase.auth.signOut();

  if (error) {
    return { message: error.message || 'Could not sign out' };
  }

  return redirect('/');
}

export async function verifyOtp(prevState: any, formData: FormData) {
  console.log('🔐 [verifyOtp Server Action] Starting OTP verification (fallback method):', {
    timestamp: new Date().toISOString(),
    note: 'This is a fallback - Route Handler should be used first',
  });
  
  const email = formData.get('email') as string;
  const token = formData.get('token') as string;
  const returnUrl = formData.get('returnUrl') as string | undefined;

  console.log('🔐 [verifyOtp Server Action] Input validation:', {
    hasEmail: !!email,
    emailLength: email?.length || 0,
    hasToken: !!token,
    tokenLength: token?.length || 0,
    returnUrl: returnUrl || '/dashboard',
    timestamp: new Date().toISOString(),
  });

  if (!email || !email.includes('@')) {
    console.error('❌ [verifyOtp Server Action] Invalid email:', { email, timestamp: new Date().toISOString() });
    return { message: 'Please enter a valid email address' };
  }

  // Normalize token: remove all non-digit characters and trim whitespace
  // This handles cases where users might paste codes with spaces, dashes, etc.
  const normalizedTokenInput = token.replace(/\D/g, '').trim();
  
  if (!normalizedTokenInput || normalizedTokenInput.length !== 6) {
    console.error('❌ [verifyOtp Server Action] Invalid token format:', {
      originalToken: token ? `${token.substring(0, 2)}****` : 'MISSING',
      originalLength: token?.length || 0,
      normalizedToken: normalizedTokenInput ? `${normalizedTokenInput.substring(0, 2)}****` : 'MISSING',
      normalizedLength: normalizedTokenInput?.length || 0,
      timestamp: new Date().toISOString(),
    });
    return { message: 'Please enter a valid 6-digit code from your email' };
  }

  console.log('🔐 [verifyOtp Server Action] Creating Supabase client...', { timestamp: new Date().toISOString() });
  const supabase = await createClient();

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedToken = normalizedTokenInput;
  
  console.log('🔐 [verifyOtp] Starting OTP verification:', {
    email: normalizedEmail,
    tokenLength: normalizedToken.length,
    returnUrl,
    timestamp: new Date().toISOString(),
  });

  // CRITICAL FIX: Backend uses generate_link with type="magiclink" but extracts email_otp
  // According to Supabase docs, email_otp from generate_link should be verified with type="email"
  // NOT type="magiclink" - magiclink type is for the actual magic link URL, not the OTP code
  // Since backend extracts email_otp and sends it as a 6-digit code, use 'email' type first
  console.log('🔐 [verifyOtp Server Action] Calling supabase.auth.verifyOtp with type=email (primary)...', {
    email: normalizedEmail,
    tokenLength: normalizedToken.length,
    type: 'email',
    reason: 'Backend extracts email_otp from generate_link - email_otp uses type="email"',
    timestamp: new Date().toISOString(),
  });

  // Try 'email' type first - this is correct for email_otp from generate_link
  let verifyResult = await supabase.auth.verifyOtp({
    email: normalizedEmail,
    token: normalizedToken,
    type: 'email', // email_otp from generate_link uses type="email"
  });
  
  // If 'email' type fails with specific error, try 'magiclink' as fallback
  // This handles edge cases where the token might be a magic link token instead
  const shouldRetryWithMagiclink = verifyResult.error && 
    verifyResult.error.code !== 'otp_expired' &&
    verifyResult.error.code !== 'expired_token' &&
    verifyResult.error.code !== 'token_expired' &&
    verifyResult.error.code !== 'invalid_token' &&
    verifyResult.error.code !== 'invalid_grant';
  
  if (shouldRetryWithMagiclink) {
    console.log('🔄 [verifyOtp Server Action] email type failed with retryable error, trying magiclink type...', {
      errorMessage: verifyResult.error?.message,
      errorCode: verifyResult.error?.code,
      timestamp: new Date().toISOString(),
    });
    
    verifyResult = await supabase.auth.verifyOtp({
      email: normalizedEmail,
      token: normalizedToken,
      type: 'magiclink', // Fallback to magiclink type
    });
  } else if (verifyResult.error) {
    console.log('⏭️ [verifyOtp Server Action] Skipping magiclink type retry - token is expired or invalid:', {
      errorMessage: verifyResult.error?.message,
      errorCode: verifyResult.error?.code,
      timestamp: new Date().toISOString(),
    });
  }
  
  const { data, error } = verifyResult;
  
  console.log('🔐 [verifyOtp Server Action] verifyOtp response received:', {
    hasData: !!data,
    hasError: !!error,
    errorMessage: error?.message,
    errorCode: error?.code,
    userId: data?.user?.id,
    hasSession: !!data?.session,
    typeUsed: error ? 'email -> magiclink (fallback)' : 'email',
    timestamp: new Date().toISOString(),
  });

  if (error) {
    console.error('❌ [verifyOtp] OTP verification failed:', {
      error: error.message,
      errorCode: error.code,
      email: email.trim().toLowerCase(),
      timestamp: new Date().toISOString(),
    });
    return { message: error.message || 'Invalid or expired code' };
  }

  console.log('✅ [verifyOtp] OTP verified successfully:', {
    userId: data.user?.id,
    email: data.user?.email,
    timestamp: new Date().toISOString(),
  });

  // Verify session is set after OTP verification
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) {
    console.error('❌ [verifyOtp] Session not created after verification:', {
      userId: data.user?.id,
      email: data.user?.email,
      timestamp: new Date().toISOString(),
    });
    return { message: 'Session not created after verification. Please try again.' };
  }

  console.log('✅ [verifyOtp] Session created successfully:', {
    userId: session.user.id,
    email: session.user.email,
    expiresAt: session.expires_at,
    expiresAtDate: session.expires_at ? new Date(session.expires_at * 1000).toISOString() : 'N/A',
    timestamp: new Date().toISOString(),
  });

  // Verify cookies are set after session creation
  const { cookies } = await import('next/headers');
  const cookieStore = await cookies();
  const allCookies = cookieStore.getAll();
  const authCookies = allCookies.filter(c => c.name.startsWith('sb-'));
  
  console.log('🍪 [verifyOtp] Cookies after session creation:', {
    totalCookies: allCookies.length,
    authCookies: authCookies.map(c => ({ name: c.name, hasValue: !!c.value, valueLength: c.value?.length || 0 })),
    timestamp: new Date().toISOString(),
  });

  // Determine if new user (for analytics)
  const isNewUser = data.user && (Date.now() - new Date(data.user.created_at).getTime()) < 60000;
  const authEvent = isNewUser ? 'signup' : 'login';

  // Use server-side redirect to ensure clean URL without token parameters
  // This prevents middleware from detecting token params and redirecting again
  const finalReturnUrl = returnUrl || '/dashboard';
  const redirectUrl = new URL(finalReturnUrl, 'http://localhost');
  redirectUrl.searchParams.set('auth_event', authEvent);
  redirectUrl.searchParams.set('auth_method', 'email_otp');
  
  console.log('🔄 [verifyOtp] Redirecting after successful verification:', {
    redirectTo: `${redirectUrl.pathname}${redirectUrl.search}`,
    authEvent,
    userId: session.user.id,
    hasSession: !!session,
    hasCookies: authCookies.length > 0,
    cookieNames: authCookies.map(c => c.name),
    timestamp: new Date().toISOString(),
  });
  
  // Revalidate the path to ensure fresh data on redirect
  // This helps ensure cookies are properly set before redirect
  revalidatePath(redirectUrl.pathname);
  
  // Server-side redirect ensures clean URL and proper session handling
  // The cookies should be set by createServerClient automatically via setAll()
  // Note: redirect() throws a NEXT_REDIRECT error which Next.js handles
  redirect(`${redirectUrl.pathname}${redirectUrl.search}`);
}
