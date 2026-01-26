import { createServerClient } from '@supabase/ssr';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { locales, defaultLocale, type Locale } from '@/i18n/config';
import { detectBestLocaleFromHeaders } from '@/lib/utils/geo-detection-server';

// Marketing pages that support locale routing for SEO (/de, /it, etc.)
const MARKETING_ROUTES = [
  '/',
  '/suna',
  '/enterprise',
  '/legal',
  '/support',
  '/templates',
];

// Routes that don't require authentication
const PUBLIC_ROUTES = [
  '/', // Homepage should be public!
  '/auth',
  '/auth/callback',
  '/auth/signup',
  '/auth/forgot-password',
  '/auth/reset-password',
  '/legal',
  '/api/auth',
  '/share', // Shared content should be public
  '/templates', // Template pages should be public
  '/enterprise', // Enterprise page should be public
  '/master-login', // Master password admin login
  '/checkout', // Public checkout wrapper for Apple compliance
  '/support', // Support page should be public
  '/suna', // Kortix rebrand page should be public for SEO
  '/help', // Help center and documentation should be public
  '/credits-explained', // Credits explained page should be public
  '/agents-101',
  '/about', // About page should be public 
  '/milano', // Milano page should be public
  '/berlin', // Berlin page should be public
  '/app', // App download page should be public,
  '/careers',
  '/pricing', // Pricing page should be public
  '/countryerror', // Country restriction error page should be public
  ...locales.flatMap(locale => MARKETING_ROUTES.map(route => `/${locale}${route === '/' ? '' : route}`)),
];

// Routes that require authentication but are related to billing/trials/setup
const BILLING_ROUTES = [
  '/activate-trial',
  '/subscription',
  '/setting-up',
];

// Routes that require authentication and active subscription
const PROTECTED_ROUTES = [
  '/dashboard',
  '/agents',
  '/projects',
  '/settings',
];

// App store links for mobile redirect
const APP_STORE_LINKS = {
  ios: 'https://apps.apple.com/ie/app/kortix/id6754448524',
  android: 'https://play.google.com/store/apps/details?id=com.kortix.app',
};

// Detect mobile platform from User-Agent header (edge-optimized)
function detectMobilePlatformFromUA(userAgent: string | null): 'ios' | 'android' | null {
  if (!userAgent) return null;
  const ua = userAgent.toLowerCase();
  if (/iphone|ipad|ipod/.test(ua)) return 'ios';
  if (/android/.test(ua)) return 'android';
  return null;
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  
  // 🚀 HYPER-FAST: Mobile app store redirect for /milano, /berlin, and /app
  // This runs at the edge before ANY page rendering
  if (pathname === '/milano' || pathname === '/berlin' || pathname === '/app') {
    const userAgent = request.headers.get('user-agent');
    const platform = detectMobilePlatformFromUA(userAgent);
    
    if (platform) {
      // Instant 302 redirect to app store - no page load needed
      return NextResponse.redirect(APP_STORE_LINKS[platform], { status: 302 });
    }
    // Desktop users continue to the full page
  }

  // Block access to WIP /thread/new route - redirect to dashboard
  if (pathname.includes('/thread/new')) {
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }
  
  // Skip middleware for static files and API routes
  // Also skip /kong/* paths - these are proxied to Supabase/Kong and should not be intercepted
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon') ||
    pathname.includes('.') ||
    pathname.startsWith('/api/') ||
    pathname.startsWith('/kong/')
  ) {
    return NextResponse.next();
  }

  // Handle Supabase verification redirects at root level
  // Supabase sometimes redirects to root (/) instead of /auth/callback
  // Detect authentication parameters and redirect to proper callback handler
  if (pathname === '/' || pathname === '') {
    const searchParams = request.nextUrl.searchParams;
    const code = searchParams.get('code');
    const token = searchParams.get('token');
    const type = searchParams.get('type');
    const error = searchParams.get('error');
    
    // If we have Supabase auth parameters, redirect to /auth/callback
    // Note: Mobile apps use direct deep links and bypass this route
    if (code || token || type || error) {
      const callbackUrl = new URL('/auth/callback', request.url);
      
      // Preserve all query parameters
      searchParams.forEach((value, key) => {
        callbackUrl.searchParams.set(key, value);
      });
      
      console.log('🔄 Redirecting Supabase verification from root to /auth/callback');
      return NextResponse.redirect(callbackUrl);
    }
  }

  // Extract path segments
  const pathSegments = pathname.split('/').filter(Boolean);
  const firstSegment = pathSegments[0];
  
  // Check if first segment is a locale (e.g., /de, /it, /de/suna)
  if (firstSegment && locales.includes(firstSegment as Locale)) {
    const locale = firstSegment as Locale;
    const remainingPath = '/' + pathSegments.slice(1).join('/') || '/';
    
    // Verify remaining path is a marketing route
    const isRemainingPathMarketing = MARKETING_ROUTES.some(route => {
      if (route === '/') {
        return remainingPath === '/' || remainingPath === '';
      }
      return remainingPath === route || remainingPath.startsWith(route + '/');
    });
    
    if (isRemainingPathMarketing) {
      // Rewrite /de to /, /de/suna to /suna, etc.
      const response = NextResponse.rewrite(new URL(remainingPath, request.url));
      response.cookies.set('locale', locale, {
        path: '/',
        maxAge: 31536000, // 1 year
        sameSite: 'lax',
      });
      
      // Store locale in headers so next-intl can pick it up
      response.headers.set('x-locale', locale);
      
      return response;
    }
  }
  
  // Check if this is a marketing route (without locale prefix)
  const isMarketingRoute = MARKETING_ROUTES.some(route => 
    pathname === route || pathname.startsWith(route + '/')
  );

  // Create a single Supabase client instance that we'll reuse
  let supabaseResponse = NextResponse.next({
    request,
  });

  // Get Supabase configuration for middleware (server-side)
  // Priority: 1) SUPABASE_URL (server-side env var), 2) NEXT_PUBLIC_SUPABASE_URL (if absolute), 3) cluster-internal default
  let supabaseUrl = (process.env.SUPABASE_URL || '').trim();
  let supabaseKey = (process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '').trim();
  
  // If server-side env var is not set, check NEXT_PUBLIC_SUPABASE_URL
  if (!supabaseUrl || supabaseUrl.trim() === '') {
    const publicUrl = (process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim();
    
    // If public URL is a relative path (e.g., /kong/auth/v1), use cluster-internal default
    // Middleware runs server-side and needs to access cluster-internal services
    if (publicUrl && publicUrl.startsWith('/')) {
      supabaseUrl = 'http://supabase-kong:8000';
    } else if (publicUrl && 
                !publicUrl.includes('demo.supabase.co') && 
                !publicUrl.includes('placeholder')) {
      // Use public URL if it's an absolute URL and not a demo/placeholder
      supabaseUrl = publicUrl;
    } else {
      // Use cluster-internal default
      supabaseUrl = 'http://supabase-kong:8000';
    }
  }
  
  // Ensure we're using cluster-internal URL for middleware (server-side)
  if (supabaseUrl.includes('demo.supabase.co') || 
      supabaseUrl.includes('placeholder') ||
      supabaseUrl.trim() === '' ||
      supabaseUrl.startsWith('/')) {
    supabaseUrl = 'http://supabase-kong:8000';
  }
  
  // Fallback: if key is empty, use demo key
  if (!supabaseKey || supabaseKey.trim() === '') {
    supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
  }
  
  console.log('[Middleware] Supabase config:', { 
    url: supabaseUrl.substring(0, 50) + '...', 
    hasKey: !!supabaseKey,
    usingServerEnv: !!process.env.SUPABASE_URL
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

  // Fetch user ONCE and reuse for both locale detection and auth checks
  let user: { id: string; email?: string; user_metadata?: { locale?: string } } | null = null;
  let authError: Error | null = null;
  
  console.log('[Middleware] 🔍 Starting auth check:', {
    pathname,
    supabaseUrl: supabaseUrl.substring(0, 50) + '...',
    hasCookies: request.cookies.getAll().length > 0,
    cookieCount: request.cookies.getAll().length
  });
  
  try {
    const { data: { user: fetchedUser }, error: fetchedError } = await supabase.auth.getUser();
    user = fetchedUser;
    authError = fetchedError as Error | null;
    
    if (fetchedError) {
      console.log('[Middleware] ❌ getUser error:', { 
        message: fetchedError.message, 
        status: fetchedError.status,
        code: (fetchedError as any).code,
        pathname,
        errorType: fetchedError.name
      });
    } else if (fetchedUser) {
      console.log('[Middleware] ✅ User authenticated:', { 
        userId: fetchedUser.id.substring(0, 8) + '...',
        email: fetchedUser.email?.substring(0, 20) + '...',
        pathname,
        hasSession: true
      });
    } else {
      console.log('[Middleware] ℹ️ No user found (unauthenticated):', {
        pathname,
        hasError: !!fetchedError
      });
    }
  } catch (error) {
    // User might not be authenticated, continue
    authError = error as Error;
    console.error('[Middleware] ❌ getUser exception:', {
      error: error instanceof Error ? error.message : String(error),
      pathname,
      stack: error instanceof Error ? error.stack : undefined
    });
  }

  // Auto-redirect based on geo-detection for marketing pages
  // Only redirect if:
  // 1. User is visiting a marketing route without locale prefix
  // 2. User doesn't have an explicit preference (no cookie, no user metadata)
  // 3. Detected locale is not English (default)
  if (isMarketingRoute && (!firstSegment || !locales.includes(firstSegment as Locale))) {
    // Check if user has explicit preference in cookie
    const localeCookie = request.cookies.get('locale')?.value;
    const hasExplicitPreference = !!localeCookie && locales.includes(localeCookie as Locale);
    
    // Check user metadata (if authenticated) - reuse the user we already fetched
    let userLocale: Locale | null = null;
    if (!hasExplicitPreference && user?.user_metadata?.locale && locales.includes(user.user_metadata.locale as Locale)) {
      userLocale = user.user_metadata.locale as Locale;
    }
    
    // Only auto-redirect if:
    // - No explicit preference (no cookie, no user metadata)
    // - Detected locale is not English (default)
    // This prevents unnecessary redirects for English speakers and users with preferences
    if (!hasExplicitPreference && !userLocale) {
      const acceptLanguage = request.headers.get('accept-language');
      
      const detectedLocale = detectBestLocaleFromHeaders(acceptLanguage);
      
      // Only redirect if detected locale is not English (default)
      // This prevents unnecessary redirects for English speakers
      if (detectedLocale !== defaultLocale) {
        const redirectUrl = new URL(request.url);
        redirectUrl.pathname = `/${detectedLocale}${pathname === '/' ? '' : pathname}`;
        
        const redirectResponse = NextResponse.redirect(redirectUrl);
        // Set cookie so we don't redirect again on next visit
        redirectResponse.cookies.set('locale', detectedLocale, {
          path: '/',
          maxAge: 31536000, // 1 year
          sameSite: 'lax',
        });
        return redirectResponse;
      }
    }
  }

  // CRITICAL: Handle authenticated users on /auth BEFORE public routes check
  // If user is authenticated and trying to access /auth, redirect them immediately
  // This prevents client-side redirect loops
  // EXCEPTION: If _reauth=true is present, allow access (user needs to reauthenticate)
  if ((pathname === '/auth' || pathname.startsWith('/auth/')) && !pathname.startsWith('/auth/callback')) {
    const reauthParam = request.nextUrl.searchParams.get('_reauth');
    const redirectParam = request.nextUrl.searchParams.get('redirect');
    
    console.log('[Middleware] 🔐 Processing /auth route:', {
      pathname,
      hasUser: !!user,
      userId: user?.id?.substring(0, 8) + '...',
      userEmail: user?.email?.substring(0, 20) + '...',
      hasAuthError: !!authError,
      authErrorType: authError?.name,
      authErrorMessage: authError?.message,
      authErrorStatus: (authError as any)?.status,
      reauthParam,
      redirectParam,
      allSearchParams: Object.fromEntries(request.nextUrl.searchParams.entries()),
      cookies: request.cookies.getAll().map(c => ({ name: c.name, hasValue: !!c.value }))
    });
    
    // If _reauth=true, allow access even if user is authenticated (they need to reauthenticate)
    if (reauthParam === 'true') {
      console.log('[Middleware] ℹ️ Allowing /auth access with _reauth=true flag:', {
        pathname,
        hasUser: !!user,
        userId: user?.id?.substring(0, 8) + '...'
      });
      // Continue to public routes check below
    } else if (user && !authError) {
      // User is authenticated - redirect to target page or dashboard
      const targetPath = redirectParam || '/dashboard';
      
      console.log('[Middleware] 🔄 Authenticated user on /auth, checking redirect:', {
        userId: user.id.substring(0, 8) + '...',
        email: user.email?.substring(0, 20) + '...',
        currentPath: pathname,
        targetPath,
        redirectParam,
        willRedirect: targetPath !== pathname,
        requestUrl: request.url
      });
      
      // Only redirect if target is different from current path
      if (targetPath !== pathname) {
        const redirectUrl = new URL(targetPath, request.url);
        // Clear redirect param to prevent loops
        redirectUrl.searchParams.delete('redirect');
        
        console.log('[Middleware] ✅ Redirecting authenticated user from /auth to:', {
          from: pathname,
          to: targetPath,
          redirectUrl: redirectUrl.toString(),
          clearedRedirectParam: true,
          userId: user.id.substring(0, 8) + '...'
        });
        
        return NextResponse.redirect(redirectUrl);
      } else {
        console.log('[Middleware] ⚠️ Target path same as current path, skipping redirect:', {
          pathname,
          targetPath
        });
      }
    } else {
      // User is not authenticated or there was an auth error
      console.log('[Middleware] ℹ️ Unauthenticated user on /auth, allowing access:', {
        pathname,
        hasUser: !!user,
        userId: user?.id?.substring(0, 8) + '...',
        hasAuthError: !!authError,
        authErrorType: authError?.name,
        authErrorMessage: authError?.message,
        authErrorStatus: (authError as any)?.status,
        reason: !user ? 'no user' : authError ? 'auth error' : 'unknown'
      });
    }
  }

  // Allow all public routes without any checks
  if (PUBLIC_ROUTES.some(route => pathname === route || pathname.startsWith(route + '/'))) {
    return NextResponse.next();
  }

  // Everything else requires authentication - reuse the user we already fetched
  try {
    // Note: /auth is already handled above (line 315-334) for authenticated users
    // and by PUBLIC_ROUTES check (line 337) for unauthenticated users
    // No need to check again here
    
    // Redirect to auth if not authenticated (using the user we already fetched)
    if (authError || !user) {
      const url = request.nextUrl.clone();
      url.pathname = '/auth';
      url.searchParams.set('redirect', pathname);
      
      console.log('[Middleware] 🔄 Redirecting unauthenticated user to /auth:', { 
        pathname, 
        hasUser: !!user, 
        hasAuthError: !!authError,
        authErrorMessage: authError?.message,
        authErrorStatus: (authError as any)?.status,
        redirectUrl: url.toString()
      });
      
      return NextResponse.redirect(url);
    }

    // Skip billing checks in local mode
    const isLocalMode = process.env.NEXT_PUBLIC_ENV_MODE?.toLowerCase() === 'local'
    if (isLocalMode) {
      return supabaseResponse;
    }

    // Skip billing checks for billing-related routes
    if (BILLING_ROUTES.some(route => pathname.startsWith(route))) {
      return supabaseResponse;
    }

    // Only check billing for protected routes that require active subscription
    // NOTE: Middleware is server-side code, so direct Supabase queries are acceptable here
    // for performance reasons. Only client-side (browser) code should use backend API.
    if (PROTECTED_ROUTES.some(route => pathname.startsWith(route))) {
      const { data: accounts } = await supabase
        .schema('basejump')
        .from('accounts')
        .select('id')
        .eq('personal_account', true)
        .eq('primary_owner_user_id', user.id)
        .single();

      if (!accounts) {
        const url = request.nextUrl.clone();
        url.pathname = '/activate-trial';
        return NextResponse.redirect(url);
      }

      const accountId = accounts.id;
      const { data: creditAccount } = await supabase
        .from('credit_accounts')
        .select('tier, trial_status, trial_ends_at')
        .eq('account_id', accountId)
        .single();

      const { data: trialHistory } = await supabase
        .from('trial_history')
        .select('id')
        .eq('account_id', accountId)
        .single();

      const hasUsedTrial = !!trialHistory;

      if (!creditAccount) {
        if (hasUsedTrial) {
          const url = request.nextUrl.clone();
          url.pathname = '/subscription';
          return NextResponse.redirect(url);
        } else {
          const url = request.nextUrl.clone();
          url.pathname = '/activate-trial';
          return NextResponse.redirect(url);
        }
      }

      const hasPaidTier = creditAccount.tier && creditAccount.tier !== 'none' && creditAccount.tier !== 'free';
      const hasFreeTier = creditAccount.tier === 'free';
      const hasActiveTrial = creditAccount.trial_status === 'active';
      const trialExpired = creditAccount.trial_status === 'expired' || creditAccount.trial_status === 'cancelled';
      const trialConverted = creditAccount.trial_status === 'converted';
      
      // If user is coming from Stripe checkout with subscription=success, allow access to dashboard
      // The webhook might not have processed yet, but we should still allow them to see the success page
      const subscriptionSuccess = request.nextUrl.searchParams.get('subscription') === 'success';
      if (subscriptionSuccess && pathname === '/dashboard') {
        return supabaseResponse;
      }
      
      if (hasPaidTier || hasFreeTier) {
        return supabaseResponse;
      }

      if (!hasPaidTier && !hasFreeTier && !hasActiveTrial && !trialConverted) {
        const url = request.nextUrl.clone();
        url.pathname = '/subscription';
        return NextResponse.redirect(url);
      } else if ((trialExpired || trialConverted) && !hasPaidTier && !hasFreeTier) {
        const url = request.nextUrl.clone();
        url.pathname = '/subscription';
        return NextResponse.redirect(url);
      }
    }

    return supabaseResponse;
  } catch (error) {
    console.error('Middleware error:', error);
    return supabaseResponse;
  }
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     * - root path (/)
     */
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
}; 