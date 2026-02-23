// GitHub API helper functions
import axios from 'axios';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || '/api',
    timeout: 600000, // 10 minutes for very large repository scanning (with parallel processing should be much faster)
    headers: {
        'Content-Type': 'application/json',
    },
});

export interface GitHubUser {
    id: number;
    login: string;
    name: string;
    email: string;
    avatar_url: string;
    html_url: string;
}

export interface Repository {
    id: number;
    name: string;
    full_name: string;
    description: string;
    html_url: string;
    clone_url: string;
    default_branch: string;
    language: string;
    private: boolean;
    updated_at: string;
}

export interface Branch {
    name: string;
    commit_sha: string;
    protected: boolean;
}

export interface RepositoryScanResult {
    scan_id: string;
    repository: string;
    branch: string;
    scan_time: string;
    total_files: number;
    scanned_files: number;
    vulnerable_files: number;
    overall_risk_score: number;
    lines_scanned?: number;
    model_used: string;
    file_results: FileResult[];
    status: string;
}

export interface FileResult {
    file_path: string;
    status: string;
    risk_score?: number;
    severity?: string;
    vulnerable?: boolean;
    highlights?: VulnerabilityHighlight[];
    suggested_fix?: string;
    reason?: string;
    error?: string;
}

export interface VulnerabilityHighlight {
    line: number;
    content: string;
    severity: string;
    type: string;
    description: string;
    fix?: string;
    confidence?: number;
}

/**
 * Initiate GitHub OAuth flow
 */
export async function initiateGitHubAuth(): Promise<{ auth_url: string; state: string }> {
    try {
        const response = await api.get('/auth/github');
        return response.data;
    } catch (error: any) {
        throw new Error(error.response?.data?.detail || 'Failed to initiate GitHub authentication');
    }
}

/**
 * Handle GitHub OAuth callback
 */
export async function handleGitHubCallback(code: string, state: string): Promise<{
    user: GitHubUser;
    access_token: string;
    github_access_token?: string
}> {
    try {
        const response = await api.post('/auth/github/callback', { code, state });
        return response.data;
    } catch (error: any) {
        throw new Error(error.response?.data?.detail || 'Failed to complete GitHub authentication');
    }
}

/**
 * Get user's GitHub repositories
 */
export async function getUserRepositories(accessToken: string): Promise<Repository[]> {
    try {
        const response = await api.get('/auth/github/repositories', {
            params: { access_token: accessToken }
        });
        return response.data.repositories;
    } catch (error: any) {
        throw new Error(error.response?.data?.detail || 'Failed to fetch repositories');
    }
}

/**
 * Get branches for a repository
 */
export async function getRepositoryBranches(repoFullName: string, accessToken: string): Promise<Branch[]> {
    try {
        const response = await api.get('/auth/github/branches', {
            params: {
                repo_full_name: repoFullName,
                access_token: accessToken
            }
        });
        return response.data.branches;
    } catch (error: any) {
        throw new Error(error.response?.data?.detail || 'Failed to fetch branches');
    }
}

/**
 * Scan a GitHub repository
 */
export async function scanRepository(
    repoUrl: string,
    branch: string,
    model: string,
    filePatterns?: string[],
    accessToken?: string,
    appToken?: string // Add app token for user identification
): Promise<RepositoryScanResult> {
    try {
        const url = appToken ? `/scan/repository?token=${appToken}` : '/scan/repository';
        console.log('[API] Sending repository scan request:', { repoUrl, branch, model });

        const response = await api.post(url, {
            repo_url: repoUrl,
            branch,
            model,
            file_patterns: filePatterns,
            access_token: accessToken
        });

        console.log('[API] Repository scan response received:', response.data);
        return response.data;
    } catch (error: any) {
        console.error('[API] Repository scan failed:', error.response?.data || error.message);
        throw new Error(error.response?.data?.detail || 'Failed to scan repository');
    }
}

/**
 * Get the decrypted GitHub access token for the current user
 */
export async function getGitHubToken(appToken: string): Promise<string> {
    try {
        const response = await api.get('/auth/github/token', {
            params: { token: appToken }
        });
        return response.data.access_token;
    } catch (error: any) {
        throw new Error(error.response?.data?.detail || 'Failed to retrieve GitHub token');
    }
}

/**
 * Get repository scan results
 */
export async function getRepositoryScan(scanId: string): Promise<RepositoryScanResult> {
    try {
        const response = await api.get(`/scan/repository/${scanId}`);
        return response.data;
    } catch (error: any) {
        throw new Error(error.response?.data?.detail || 'Failed to fetch scan results');
    }
}
