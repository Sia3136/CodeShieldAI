import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/app/components/ui/card';
import { User, Mail, Calendar } from 'lucide-react';
import { ScanHistory } from '@/app/components/ScanHistory';
import { type User as UserType } from '@/lib/auth-api';

interface UserAccountPageProps {
    user: UserType;
}

export function UserAccountPage({ user }: UserAccountPageProps) {
    const formatDate = (dateString?: string | null) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    };

    return (
        <div className="space-y-6">
            {/* User Profile Card */}
            <Card className="bg-white dark:bg-slate-900 border-slate-200 dark:border-white/10">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-slate-900 dark:text-white">
                        <User className="w-5 h-5" />
                        Account Information
                    </CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="space-y-4">
                        <div className="flex items-center gap-3">
                            {user.avatar_url ? (
                                <img
                                    src={user.avatar_url}
                                    alt={user.name}
                                    className="w-16 h-16 rounded-full border-2 border-blue-500 shadow-lg object-cover"
                                />
                            ) : (
                                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center text-white text-2xl font-bold">
                                    {(user.name || user.email || '?').charAt(0).toUpperCase()}
                                </div>
                            )}
                            <div>
                                <h3 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                                    {user.name}
                                    {user.username && (
                                        <span className="text-sm font-mono text-blue-500">(@{user.username})</span>
                                    )}
                                </h3>
                                <p className="text-sm text-slate-600 dark:text-white/60 flex items-center gap-1">
                                    <Mail className="w-3 h-3" />
                                    {user.email}
                                </p>
                            </div>
                        </div>

                        <div className="pt-4 border-t border-slate-200 dark:border-white/10">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <p className="text-xs text-slate-500 dark:text-white/50 mb-1">Authentication Provider</p>
                                    <p className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                                        <span className="px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-300 text-xs uppercase">
                                            {user.auth_provider || (user.username ? 'GitHub' : user.email.includes('google') ? 'Google' : 'Email')}
                                        </span>
                                    </p>
                                </div>
                                <div>
                                    <p className="text-xs text-slate-500 dark:text-white/50 mb-1">Member Since</p>
                                    <p className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-1">
                                        <Calendar className="w-3 h-3" />
                                        {formatDate(user.created_at)}
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </CardContent>
            </Card>

            {/* Scan History */}
            <ScanHistory />
        </div>
    );
}
