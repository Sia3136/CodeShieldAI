import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/app/components/ui/card';
import { Button } from '@/app/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/app/components/ui/avatar';
import { Github, LogOut, User } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { toast } from 'sonner';
import { initiateGitHubAuth, handleGitHubCallback, type GitHubUser } from '@/lib/github-api';

interface GitHubAuthProps {
    onAuthChange?: (user: GitHubUser | null, token: string | null) => void;
}

export function GitHubAuth({ onAuthChange }: GitHubAuthProps) {
    const [user, setUser] = useState<GitHubUser | null>(null);
    const [accessToken, setAccessToken] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    // Check for existing session on mount
    useEffect(() => {
        const storedUser = localStorage.getItem('github_user');
        const storedToken = localStorage.getItem('github_token');

        if (storedUser && storedToken) {
            try {
                const parsedUser = JSON.parse(storedUser);
                setUser(parsedUser);
                setAccessToken(storedToken);
                onAuthChange?.(parsedUser, storedToken);
            } catch (e) {
                localStorage.removeItem('github_user');
                localStorage.removeItem('github_token');
            }
        }

        // ── Listen for OAuth callback (popup flow) ──
        const bc = new BroadcastChannel('codeshield_oauth');
        bc.onmessage = (ev) => {
            if (ev.data?.type === 'oauth_code_received' && ev.data?.provider === 'github') {
                handleCallback(ev.data.code, ev.data.state || '');
            }
        };

        // Also check sessionStorage (fallback when BroadcastChannel is blocked)
        const checkStorage = () => {
            const pending = sessionStorage.getItem('oauth_payload');
            if (pending) {
                sessionStorage.removeItem('oauth_payload');
                try {
                    const d = JSON.parse(pending);
                    if (d.provider === 'github' && d.code) {
                        handleCallback(d.code, d.state || '');
                    }
                } catch { }
            }
        };
        const storageInterval = setInterval(checkStorage, 500);

        // Handle message events from popup
        const handleMessage = (event: MessageEvent) => {
            if (event.data?.type === 'oauth_code_received' && event.data?.provider === 'github') {
                handleCallback(event.data.code, event.data.state || '');
            }
        };
        window.addEventListener('message', handleMessage);

        return () => {
            bc.close();
            clearInterval(storageInterval);
            window.removeEventListener('message', handleMessage);
        };
    }, []);

    const handleCallback = async (code: string, state: string) => {
        setLoading(true);
        try {
            const result = await handleGitHubCallback(code, state);

            // Store in localStorage
            localStorage.setItem('github_user', JSON.stringify(result.user));
            const scanToken = result.github_access_token || result.access_token;
            localStorage.setItem('github_token', scanToken);

            setUser(result.user);
            setAccessToken(scanToken);
            onAuthChange?.(result.user, scanToken);

            toast.success(`Welcome, ${result.user.login}!`);
        } catch (error: any) {
            toast.error(error.message || 'Authentication failed');
        } finally {
            setLoading(false);
        }
    };

    const handleLogin = async () => {
        setLoading(true);
        try {
            const { auth_url } = await initiateGitHubAuth();

            // FULL PAGE REDIRECT
            window.location.href = auth_url;

        } catch (error: any) {
            toast.error(error.message || 'Failed to initiate authentication');
            setLoading(false);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('github_user');
        localStorage.removeItem('github_token');
        sessionStorage.removeItem('github_oauth_state');

        setUser(null);
        setAccessToken(null);
        onAuthChange?.(null, null);

        toast.success('Logged out successfully');
    };

    if (user) {
        return (
            <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="flex items-center gap-3 bg-white/60 dark:bg-slate-900/60 backdrop-blur-md px-4 py-2.5 rounded-xl border border-slate-200/70 dark:border-slate-700/70 shadow-sm"
            >
                <Avatar className="h-8 w-8">
                    <AvatarImage src={user.avatar_url} alt={user.login} />
                    <AvatarFallback>
                        <User className="h-4 w-4" />
                    </AvatarFallback>
                </Avatar>

                <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                        {user.name || user.login}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                        @{user.login}
                    </p>
                </div>

                <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleLogout}
                    className="text-slate-600 dark:text-slate-400 hover:text-red-600 dark:hover:text-red-400"
                >
                    <LogOut className="h-4 w-4" />
                </Button>
            </motion.div>
        );
    }

    return (
        <Button
            onClick={handleLogin}
            disabled={loading}
            className="bg-gradient-to-r from-slate-800 to-slate-900 hover:from-slate-700 hover:to-slate-800 text-white shadow-lg"
        >
            <Github className="w-4 h-4 mr-2" />
            {loading ? 'Connecting...' : 'Connect with GitHub'}
        </Button>
    );
}
