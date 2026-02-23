import axios from 'axios';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || '/api',
    timeout: 60000,  // 60s — HF free-tier spaces may take up to 30s to wake up
    headers: {
        'Content-Type': 'application/json',
    },
});

export interface RegisterData {
    email: string;
    password: string;
    name?: string;
}

export interface LoginData {
    email: string;
    password: string;
}

export interface AuthResponse {
    access_token: string;
    token_type: string;
}

export interface User {
    email: string;
    name: string;
    username?: string;
    avatar_url?: string;
    auth_provider?: 'email' | 'google' | 'github';
    created_at: string;
    last_login: string | null;
}

export async function register(data: RegisterData): Promise<AuthResponse> {
    const response = await api.post('/auth/register', data);
    return response.data;
}

export async function login(data: LoginData): Promise<AuthResponse> {
    const response = await api.post('/auth/login', data);
    return response.data;
}

export async function getCurrentUser(token: string): Promise<User> {
    const response = await api.get(`/auth/me?token=${token}`);
    return response.data;
}

// Token management
export function saveToken(token: string) {
    localStorage.setItem('auth_token', token);
}

export function getToken(): string | null {
    return localStorage.getItem('auth_token');
}

export function removeToken() {
    localStorage.removeItem('auth_token');
}
