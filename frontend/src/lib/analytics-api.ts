import axios from 'axios';

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

export interface ScanHistoryItem {
    scan_time: string;
    vulnerable: boolean;
    risk_score: number;
    severity: string;
    code_snippet: string;
    highlights?: string | VulnerabilityHighlight[];
    suggested_fix?: string;
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
    const token = localStorage.getItem('auth_token');
    const url = token ? `/analytics/scan-history?limit=${limit}&token=${token}` : `/analytics/scan-history?limit=${limit}`;
    const response = await api.get(url);
    return response.data;
}
