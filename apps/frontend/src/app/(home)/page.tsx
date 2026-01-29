'use client';

import { Suspense, lazy, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { BackgroundAALChecker } from '@/components/auth/background-aal-checker';
import { HeroSection as NewHeroSection } from '@/components/home/hero-section';

// Lazy load components
const MobileAppInterstitial = lazy(() =>
  import('@/components/announcements/mobile-app-interstitial').then(mod => ({ default: mod.MobileAppInterstitial }))
);

export default function Home() {
  const router = useRouter();
  
  // 🚨 TEMPORARY: Redirect to dashboard immediately
  // TODO: Remove this when authentication is fixed
  useEffect(() => {
    const disableAuth = true; // Set to false to re-enable home page
    if (disableAuth) {
      console.log('🚨 [Home] Redirecting to dashboard (auth disabled)');
      router.replace('/dashboard');
      return;
    }
  }, [router]);
  
  // Prevent body scroll on home page only
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  return (
    <BackgroundAALChecker>
      <div className="h-dvh overflow-hidden">
        <NewHeroSection />
        {/* Mobile app banner - shown on mobile devices for logged-in users */}
        <Suspense fallback={null}>
          <MobileAppInterstitial />
        </Suspense>
      </div>
    </BackgroundAALChecker>
  );
}
