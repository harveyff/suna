// Force all dashboard pages to be dynamically rendered to avoid Supabase client initialization failures during build
export const dynamic = 'force-dynamic';
export const revalidate = 0;

import DashboardLayoutContent from '@/components/dashboard/layout-content';

interface DashboardLayoutProps {
  children: React.ReactNode;
}

export default function DashboardLayout({
  children,
}: DashboardLayoutProps) {
  return <DashboardLayoutContent>{children}</DashboardLayoutContent>;
}
