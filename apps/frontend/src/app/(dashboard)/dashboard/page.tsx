import { cn } from "@/lib/utils";
import { DashboardContent } from "../../../components/dashboard/dashboard-content";
import { BackgroundAALChecker } from "@/components/auth/background-aal-checker";
import { Suspense } from "react";
import { Skeleton } from "@/components/ui/skeleton";

// Force dynamic rendering to avoid build-time errors
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export default async function DashboardPage() {
  try {
    return (
      <BackgroundAALChecker>
        <Suspense
          fallback={
            <div className="flex flex-col h-full w-full">
              <div className="flex-1 flex flex-col items-center justify-center px-4">
                <div className={cn(
                  "flex flex-col items-center text-center w-full space-y-8",
                  "max-w-[850px] sm:max-w-full sm:px-4"
                )}>
                  <Skeleton className="h-10 w-40 sm:h-8 sm:w-32" />
                  <Skeleton className="h-7 w-56 sm:h-6 sm:w-48" />
                  <Skeleton className="w-full h-[100px] rounded-xl sm:h-[80px]" />
                  <div className="block sm:hidden lg:block w-full">
                    <Skeleton className="h-20 w-full" />
                  </div>
                </div>
              </div>
            </div>
          }
        >
          <DashboardContent />
        </Suspense>
      </BackgroundAALChecker>
    );
  } catch (error) {
    console.error('❌ [DashboardPage] Server-side rendering error:', {
      error: error instanceof Error ? error.message : String(error),
      errorStack: error instanceof Error ? error.stack : undefined,
      timestamp: new Date().toISOString(),
    });
    
    // Return a simple error page instead of crashing
    return (
      <div className="flex flex-col h-full w-full items-center justify-center p-4">
        <div className="text-center space-y-4">
          <h1 className="text-2xl font-semibold">Something went wrong</h1>
          <p className="text-muted-foreground">Please try refreshing the page.</p>
        </div>
      </div>
    );
  }
}