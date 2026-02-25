import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { X, Mail, Lock, User, LogIn, UserPlus, Github as GithubIcon } from 'lucide-react';
import { Button } from '@/app/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/app/components/ui/card';
import { Input } from '@/app/components/ui/input';
import { Label } from '@/app/components/ui/label';
import { toast } from 'sonner';
import { register, login, saveToken, type RegisterData, type LoginData } from '@/lib/auth-api';

interface AuthModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

export function AuthModal({ isOpen, onClose, onSuccess }: AuthModalProps) {
    const [mode, setMode] = useState<'login' | 'register'>('login');
    const [loading, setLoading] = useState(false);
    const [formData, setFormData] = useState({
        email: '',
        password: '',
        name: '',
    });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);

        try {
            let response;
            if (mode === 'register') {
                const data: RegisterData = {
                    email: formData.email,
                    password: formData.password,
                    name: formData.name || undefined,
                };
                response = await register(data);
                toast.success('Account created successfully!');
            } else {
                const data: LoginData = {
                    email: formData.email,
                    password: formData.password,
                };
                response = await login(data);
                toast.success('Logged in successfully!');
            }

            // Save token
            saveToken(response.access_token);

            // Reset form
            setFormData({ email: '', password: '', name: '' });

            // Call success callback
            onSuccess();
            onClose();
        } catch (error: any) {
            console.error('Auth error:', error);
            const message = error.response?.data?.detail || 'Authentication failed';
            toast.error(message);
        } finally {
            setLoading(false);
        }
    };

    const handleOAuthLogin = async (provider: 'google' | 'github') => {
        try {
            // Get OAuth URL from backend
            const apiBase = import.meta.env.VITE_API_URL || '/api';
            const response = await fetch(`${apiBase}/auth/${provider}`);
            const data = await response.json();

            if (!data.auth_url) {
                throw new Error('Failed to get OAuth URL');
            }

            // Open OAuth popup
            const width = 600;
            const height = 700;
            const left = window.screenX + (window.outerWidth - width) / 2;
            const top = window.screenY + (window.outerHeight - height) / 2;

            const popup = window.open(
                data.auth_url,
                `${provider}_oauth`,
                `width=${width},height=${height},left=${left},top=${top},toolbar=no,menubar=no`
            );

            if (!popup) {
                // Popup blocked — fall back to full-page redirect.
                // callback.html will save the token and redirect back.
                window.location.href = data.auth_url;
                return;
            }

            // ── Listen for message from callback.html ─────────────────────
            // callback.html now does the full exchange, saves token, and
            // sends { type: 'oauth_complete', provider, token } via postMessage.
            const handleMessage = (event: MessageEvent) => {
                if (event.origin !== window.location.origin) return;

                if (event.data.type === 'oauth_complete' && event.data.provider === provider) {
                    cleanup();
                    popup?.close();

                    // Token is already in localStorage (saved by callback.html)
                    // But also save it explicitly in case
                    if (event.data.token) {
                        saveToken(event.data.token);
                    }

                    console.log(`[Auth] ${provider} login complete`);
                    toast.success(`Logged in with ${provider.charAt(0).toUpperCase() + provider.slice(1)}!`);

                    setTimeout(() => {
                        onSuccess();
                        onClose();
                    }, 100);
                }

                if (event.data.type === 'oauth_error' && event.data.provider === provider) {
                    cleanup();
                    popup?.close();
                    toast.error(event.data.error || 'OAuth authentication failed');
                }
            };

            window.addEventListener('message', handleMessage);

            // BroadcastChannel fallback
            let bc: BroadcastChannel | null = null;
            try {
                bc = new BroadcastChannel('codeshield_oauth');
                bc.onmessage = (evt) => {
                    handleMessage({ ...evt, origin: window.location.origin } as MessageEvent);
                };
            } catch (_) { /* BroadcastChannel not supported */ }

            // ── When popup closes, check if token landed in localStorage ──
            const checkClosed = setInterval(() => {
                try {
                    if (popup?.closed) {
                        clearInterval(checkClosed);

                        // Give a small delay for any last message to arrive
                        setTimeout(() => {
                            const token = localStorage.getItem('auth_token');
                            if (token) {
                                // callback.html saved the token — login succeeded!
                                cleanup();
                                console.log('[Auth] Token found in localStorage after popup closed');
                                toast.success(`Logged in with ${provider.charAt(0).toUpperCase() + provider.slice(1)}!`);
                                onSuccess();
                                onClose();
                            } else {
                                cleanup();
                                // No token — user likely cancelled or flow failed
                                console.log('[Auth] Popup closed without token');
                            }
                        }, 500);
                    }
                } catch (e) {
                    // Ignore COOP errors like "Cross-Origin-Opener-Policy would block the window.closed call"
                    // We just keep polling until the popup is either closed by the user or closes itself.
                }
            }, 500);

            function cleanup() {
                clearInterval(checkClosed);
                window.removeEventListener('message', handleMessage);
                bc?.close();
            }

        } catch (error: any) {
            console.error('OAuth error:', error);
            toast.error(`Failed to login with ${provider}`);
        }
    };

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.2 }}
                    className="w-full max-w-md"
                >
                    <Card className="bg-white dark:bg-slate-900 border-slate-200 dark:border-white/10 shadow-2xl">
                        <CardHeader className="relative">
                            <button
                                onClick={onClose}
                                className="absolute top-4 right-4 p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-white/10 transition-colors"
                            >
                                <X className="w-5 h-5" />
                            </button>
                            <CardTitle className="text-2xl text-slate-900 dark:text-white">
                                {mode === 'login' ? 'Welcome Back' : 'Create Account'}
                            </CardTitle>
                            <CardDescription className="text-slate-600 dark:text-white/60">
                                {mode === 'login'
                                    ? 'Sign in to access your dashboard'
                                    : 'Get started with CodeShieldAI'}
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-6">
                            <form onSubmit={handleSubmit} className="space-y-4">
                                {mode === 'register' && (
                                    <div className="space-y-2">
                                        <Label htmlFor="name" className="text-slate-900 dark:text-white">
                                            Name (optional)
                                        </Label>
                                        <div className="relative">
                                            <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                                            <Input
                                                id="name"
                                                type="text"
                                                placeholder="John Doe"
                                                value={formData.name}
                                                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                                className="pl-10 bg-slate-50 dark:bg-white/5 border-slate-200 dark:border-white/10"
                                            />
                                        </div>
                                    </div>
                                )}

                                <div className="space-y-2">
                                    <Label htmlFor="email" className="text-slate-900 dark:text-white">
                                        Email
                                    </Label>
                                    <div className="relative">
                                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                                        <Input
                                            id="email"
                                            type="email"
                                            placeholder="you@example.com"
                                            value={formData.email}
                                            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                                            required
                                            className="pl-10 bg-slate-50 dark:bg-white/5 border-slate-200 dark:border-white/10"
                                        />
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="password" className="text-slate-900 dark:text-white">
                                        Password
                                    </Label>
                                    <div className="relative">
                                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                                        <Input
                                            id="password"
                                            type="password"
                                            placeholder="••••••••"
                                            value={formData.password}
                                            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                                            required
                                            minLength={6}
                                            className="pl-10 bg-slate-50 dark:bg-white/5 border-slate-200 dark:border-white/10"
                                        />
                                    </div>
                                </div>

                                <Button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white"
                                >
                                    {loading ? (
                                        'Processing...'
                                    ) : mode === 'login' ? (
                                        <>
                                            <LogIn className="w-4 h-4 mr-2" />
                                            Sign In
                                        </>
                                    ) : (
                                        <>
                                            <UserPlus className="w-4 h-4 mr-2" />
                                            Create Account
                                        </>
                                    )}
                                </Button>
                            </form>

                            <div className="relative">
                                <div className="absolute inset-0 flex items-center">
                                    <div className="w-full border-t border-slate-200 dark:border-white/10" />
                                </div>
                                <div className="relative flex justify-center text-sm">
                                    <span className="px-2 bg-white dark:bg-slate-900 text-slate-500 dark:text-white/60">
                                        Or continue with
                                    </span>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <Button
                                    type="button"
                                    variant="outline"
                                    onClick={() => handleOAuthLogin('google')}
                                    className="bg-white dark:bg-white/5 border-slate-200 dark:border-white/10"
                                >
                                    <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                                    </svg>
                                    Google
                                </Button>
                                <Button
                                    type="button"
                                    variant="outline"
                                    onClick={() => handleOAuthLogin('github')}
                                    className="bg-white dark:bg-white/5 border-slate-200 dark:border-white/10"
                                >
                                    <GithubIcon className="w-5 h-5 mr-2" />
                                    GitHub
                                </Button>
                            </div>

                            <div className="text-center text-sm">
                                <span className="text-slate-600 dark:text-white/60">
                                    {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
                                </span>
                                {' '}
                                <button
                                    type="button"
                                    onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
                                    className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
                                >
                                    {mode === 'login' ? 'Sign up' : 'Sign in'}
                                </button>
                            </div>
                        </CardContent>
                    </Card>
                </motion.div>
            </div>
        </AnimatePresence>
    );
}
