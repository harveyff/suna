'use client';

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  ReactNode,
} from 'react';
import { createClient } from '@/lib/supabase/client';
import { User, Session } from '@supabase/supabase-js';
import { SupabaseClient } from '@supabase/supabase-js';
import { clearUserLocalStorage } from '@/lib/utils/clear-local-storage';
// Auth tracking moved to AuthEventTracker component (handles OAuth redirects)

type AuthContextType = {
  supabase: SupabaseClient;
  session: Session | null;
  user: User | null;
  isLoading: boolean;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const supabase = createClient();
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const getInitialSession = async () => {
      console.log('🔄 [AuthProvider] Starting session initialization...', {
        timestamp: new Date().toISOString(),
      });
      
      try {
        const {
          data: { session: currentSession },
          error: sessionError,
        } = await supabase.auth.getSession();
        
        if (sessionError) {
          console.error('❌ [AuthProvider] Error getting session:', {
            error: sessionError.message,
            errorCode: sessionError.code,
            timestamp: new Date().toISOString(),
          });
        }
        
        console.log('🔍 [AuthProvider] Session check result:', {
          hasSession: !!currentSession,
          hasUser: !!currentSession?.user,
          userId: currentSession?.user?.id,
          email: currentSession?.user?.email,
          expiresAt: currentSession?.expires_at,
          timestamp: new Date().toISOString(),
        });
        
        setSession(currentSession);
        setUser(currentSession?.user ?? null);
        
        console.log('✅ [AuthProvider] Session initialized:', {
          hasSession: !!currentSession,
          hasUser: !!currentSession?.user,
          userId: currentSession?.user?.id,
          timestamp: new Date().toISOString(),
        });
      } catch (error) {
        console.error('❌ [AuthProvider] Unexpected error during session initialization:', {
          error: error instanceof Error ? error.message : String(error),
          timestamp: new Date().toISOString(),
        });
      } finally {
        setIsLoading(false);
        console.log('✅ [AuthProvider] Loading completed:', {
          isLoading: false,
          timestamp: new Date().toISOString(),
        });
      }
    };

    getInitialSession();

    const { data: authListener } = supabase.auth.onAuthStateChange(
      async (event, newSession) => {
        console.log('🔄 [AuthProvider] Auth state change event:', {
          event,
          hasSession: !!newSession,
          hasUser: !!newSession?.user,
          userId: newSession?.user?.id,
          email: newSession?.user?.email,
          timestamp: new Date().toISOString(),
        });
        
        setSession(newSession);
        setUser(newSession?.user ?? null);

        if (isLoading) setIsLoading(false);
        switch (event) {
          case 'SIGNED_IN':
            console.log('✅ [AuthProvider] User signed in:', {
              userId: newSession?.user?.id,
              email: newSession?.user?.email,
              timestamp: new Date().toISOString(),
            });
            // Auth tracking handled by AuthEventTracker component via URL params
            break;
          case 'SIGNED_OUT':
            console.log('🚪 [AuthProvider] User signed out:', {
              timestamp: new Date().toISOString(),
            });
            clearUserLocalStorage();
            break;
          case 'TOKEN_REFRESHED':
            console.log('🔄 [AuthProvider] Token refreshed:', {
              userId: newSession?.user?.id,
              timestamp: new Date().toISOString(),
            });
            break;
          case 'MFA_CHALLENGE_VERIFIED':
            console.log('✅ [AuthProvider] MFA challenge verified:', {
              userId: newSession?.user?.id,
              timestamp: new Date().toISOString(),
            });
            break;
          default:
            console.log('ℹ️ [AuthProvider] Unhandled auth event:', {
              event,
              timestamp: new Date().toISOString(),
            });
        }
      },
    );

    return () => {
      authListener?.subscription.unsubscribe();
    };
  }, [supabase]); // Removed isLoading from dependencies to prevent infinite loops

  const signOut = async () => {
    try {
      await supabase.auth.signOut();
      // Clear local storage after successful sign out
      clearUserLocalStorage();
    } catch (error) {
      console.error('❌ Error signing out:', error);
    }
  };

  const value = {
    supabase,
    session,
    user,
    isLoading,
    signOut,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
