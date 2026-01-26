'use client';

import { useQuery } from '@tanstack/react-query';
import { backendApi } from '@/lib/api-client';

export interface IMaintenanceNotice {
  enabled: boolean;
  startTime?: string;
  endTime?: string;
}

export interface ITechnicalIssue {
  enabled: boolean;
  message?: string;
  statusUrl?: string;
  affectedServices?: string[];
  description?: string;
  estimatedResolution?: string;
  severity?: 'degraded' | 'outage' | 'maintenance';
}

export interface SystemStatusResponse {
  maintenanceNotice: IMaintenanceNotice;
  technicalIssue: ITechnicalIssue;
  updatedAt?: string;
}

async function fetchSystemStatus(): Promise<SystemStatusResponse> {
  try {
    // Use backendApi client which handles URL construction correctly
    // It uses NEXT_PUBLIC_BACKEND_URL which should be relative path /v1 for same-origin requests
    const result = await backendApi.get<SystemStatusResponse>('/system/status', {
      showErrors: false, // Don't show errors for system status checks
    });
    
    if (!result.success || result.error) {
      console.warn('Failed to fetch system status:', result.error?.message || 'Unknown error');
      return {
        maintenanceNotice: { enabled: false },
        technicalIssue: { enabled: false },
      };
    }
    
    return result.data || {
      maintenanceNotice: { enabled: false },
      technicalIssue: { enabled: false },
    };
  } catch (error) {
    console.warn('Failed to fetch system status:', error);
    return {
      maintenanceNotice: { enabled: false },
      technicalIssue: { enabled: false },
    };
  }
}

export const systemStatusKeys = {
  all: ['system-status'] as const,
} as const;

export const useSystemStatusQuery = (options?: { enabled?: boolean }) => {
  return useQuery<SystemStatusResponse>({
    queryKey: systemStatusKeys.all,
    queryFn: fetchSystemStatus,
    staleTime: 30 * 1000,
    refetchInterval: 60 * 1000,
    refetchOnWindowFocus: true,
    refetchOnMount: 'always',
    retry: 2,
    placeholderData: {
      maintenanceNotice: { enabled: false },
      technicalIssue: { enabled: false },
    },
    ...options,
  });
};

export const useMaintenanceNoticeQuery = (options?: { enabled?: boolean }) => {
  const { data, ...rest } = useSystemStatusQuery(options);
  return {
    ...rest,
    data: data?.maintenanceNotice || { enabled: false } as IMaintenanceNotice,
  };
};

export const useTechnicalIssueQuery = (options?: { enabled?: boolean }) => {
  const { data, ...rest } = useSystemStatusQuery(options);
  return {
    ...rest,
    data: data?.technicalIssue || { enabled: false } as ITechnicalIssue,
  };
};
