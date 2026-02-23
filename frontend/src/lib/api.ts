// src/lib/api.ts
import axios from 'axios';

// Create axios instance with base URL
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 120000,           // 120s — HF free-tier spaces need up to 90s on cold start
  headers: {
    'Content-Type': 'application/json',
  },
});

export async function scanCode(code: string, model: string = 'GraphCodeBERT', filename: string = 'snippet'): Promise<any> {
  if (!code?.trim()) {
    throw new Error('Please paste some code first');
  }

  const token = localStorage.getItem('auth_token');
  const url = token ? `/scan?token=${token}` : '/scan';

  // Retry once on network errors (handles HF Space cold-start drops)
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const response = await api.post(url, { code, model, filename });
      return response.data;
    } catch (err: any) {
      const isNetworkError = !err.response && (err.message === 'Network Error' || err.code === 'ERR_NETWORK');
      const isTimeout = err.code === 'ECONNABORTED';

      if (isNetworkError && attempt === 1) {
        // First attempt failed with a network error — wait 3s and retry once
        console.warn('[Scan] Network error on attempt 1, retrying in 3s...');
        await new Promise(res => setTimeout(res, 3000));
        continue;
      }

      console.error('Scan failed:', err);
      if (err.response?.data?.detail) {
        throw new Error(err.response.data.detail);
      }
      if (isTimeout) {
        throw new Error('Request timed out. The backend may be waking up — please try again in a moment.');
      }
      if (isNetworkError) {
        throw new Error('Could not reach the scanner. The backend may be starting up — please wait a few seconds and try again.');
      }
      throw new Error(err.message || 'Could not reach the scanner');
    }
  }
}

// Helper for severity styles (from user requirement)
export function getSeverityStyle(severity: string = 'Low'): string {
  const styles: Record<string, string> = {
    Critical: 'bg-red-600 text-white border-red-700',
    High: 'bg-orange-500 text-white border-orange-600',
    Medium: 'bg-yellow-500 text-black border-yellow-600',
    Low: 'bg-green-600 text-white border-green-700',
  };
  // Case insensitive match attempt
  const key = Object.keys(styles).find(k => k.toLowerCase() === severity.toLowerCase());
  return key ? styles[key] : 'bg-gray-500 text-white border-gray-600';
}