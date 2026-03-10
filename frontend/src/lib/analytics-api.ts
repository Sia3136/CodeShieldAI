import axios from 'axios';
import { getToken } from './auth-api';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || '/api',
    timeout: 30000,
    headers: {
        'Content-Type': 'application/json',
    },
});

export interface AnalyticsMetrics {
    scans_today: number;
    high_medium_vulnerabilities: number;
    active_users_7d: number;
    last_updated: string;
}

export type ScanType = 'snippet' | 'upload' | 'github';

export interface ScanHistoryItem {
    // Common fields
    scan_time: string;
    scan_type: ScanType;
    target: string;           // filename for snippet/upload, repo full_name for github
    vulnerable: boolean;
    risk_score: number;
    severity: string;

    // Snippet / upload only
    code_snippet?: string;
    highlights?: string | VulnerabilityHighlight[];
    suggested_fix?: string;
    filename?: string;        // kept for backward compat with legacy records

    // GitHub scan only
    branch?: string;
    scanned_files?: number;
    vulnerable_files?: number;
    scan_id?: string;
}

export interface VulnerabilityHighlight {
    line: number;
    content: string;
    severity: string;
    type: string;
    description: string;
    fix?: string;
}

export interface ScanHistoryResponse {
    scans: ScanHistoryItem[];
    total: number;
}

export async function getAnalyticsMetrics(): Promise<AnalyticsMetrics> {
    const response = await api.get('/analytics/metrics');
    return response.data;
}

export async function getScanHistory(limit: number = 50): Promise<ScanHistoryResponse> {
    // Always attach the auth token — the backend enforces isolation and returns
    // an empty list when no valid token is present (no cross-user data leakage).
    const token = localStorage.getItem('auth_token') || getToken();
    if (!token) {
        // No session — return empty immediately without touching the API
        return { scans: [], total: 0 };
    }
    const url = `/analytics/scan-history?limit=${limit}&token=${token}`;
    const response = await api.get(url);
    return response.data;
}
