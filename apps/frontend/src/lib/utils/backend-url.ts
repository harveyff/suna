/**
 * Get backend API URL with normalization to avoid mixed content errors
 * Priority: 1) Runtime config from window, 2) Build-time env var, 3) Default relative path
 * Always returns a relative path (starting with /) to ensure same-origin requests
 * 
 * This function should be used everywhere instead of directly accessing process.env.NEXT_PUBLIC_BACKEND_URL
 * to ensure consistent URL handling and prevent mixed content errors.
 */
export function getBackendUrl(): string {
  let backendUrl = '';
  
  // Strategy 1: Get from window.__BACKEND_CONFIG__ (runtime injection from server)
  if (typeof window !== 'undefined') {
    const windowConfig = (window as any).__BACKEND_CONFIG__;
    if (windowConfig && typeof windowConfig === 'object' && windowConfig.url) {
      backendUrl = String(windowConfig.url).trim();
    }
  }
  
  // Strategy 2: Get from build-time environment variable
  if (!backendUrl) {
    backendUrl = (process.env.NEXT_PUBLIC_BACKEND_URL || '').trim();
  }
  
  // Strategy 3: Default to relative path
  if (!backendUrl) {
    backendUrl = '/v1';
  }
  
  // Normalize URL: Convert absolute URLs to relative paths
  // This prevents mixed content errors when HTTPS page tries to load HTTP resources
  try {
    // If it's an absolute URL (starts with http:// or https://)
    if (backendUrl.startsWith('http://') || backendUrl.startsWith('https://')) {
      const url = new URL(backendUrl);
      // Extract the pathname, default to /v1 if pathname is empty
      backendUrl = url.pathname || '/v1';
      // Ensure it starts with /
      if (!backendUrl.startsWith('/')) {
        backendUrl = '/' + backendUrl;
      }
      // Log warning in development
      if (typeof window !== 'undefined' && process.env.NODE_ENV === 'development') {
        console.warn('[Backend URL] Converted absolute backend URL to relative path:', {
          original: process.env.NEXT_PUBLIC_BACKEND_URL,
          normalized: backendUrl
        });
      }
    }
  } catch (e) {
    // If URL parsing fails, use default
    backendUrl = '/v1';
  }
  
  // Ensure it starts with / (relative path)
  if (!backendUrl.startsWith('/')) {
    backendUrl = '/' + backendUrl;
  }
  
  // Remove trailing slash
  backendUrl = backendUrl.replace(/\/$/, '');
  
  return backendUrl || '/v1';
}

/**
 * Build a full backend API URL from an endpoint path
 * @param endpoint - API endpoint path (e.g., '/billing/trial/start' or 'billing/trial/start')
 * @returns Full URL path (e.g., '/v1/billing/trial/start')
 */
export function buildBackendUrl(endpoint: string): string {
  const baseUrl = getBackendUrl();
  const normalizedEndpoint = endpoint.startsWith('/') ? endpoint : '/' + endpoint;
  return `${baseUrl}${normalizedEndpoint}`;
}

