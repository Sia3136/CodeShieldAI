import React, { useState, useEffect } from 'react';
import { getCurrentUser, getToken, removeToken, type User as UserType } from '@/lib/auth-api';

interface UserProfileButtonProps {
    onLogout?: () => void;
    onViewAccount?: () => void;
}

export function UserProfileButton({ onLogout, onViewAccount }: UserProfileButtonProps) {
    const [user, setUser] = useState<UserType | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchUser = async () => {
            const token = getToken();
            if (token) {
                try {
                    const userData = await getCurrentUser(token);
                    setUser(userData);
                } catch (error) {
                    console.error('Failed to fetch user:', error);
                    // Token might be invalid, remove it
                    removeToken();
                }
            }
            setLoading(false);
        };

        fetchUser();
    }, []);

    if (loading || !user) {
        return null;
    }

    const getInitials = () => {
        if (!user) return '';
        const name = user.name || user.username || user.email.split('@')[0];
        return name.substring(0, 2).toUpperCase();
    };

    const getDisplayName = () => {
        if (!user) return '';
        return user.name || user.username || user.email.split('@')[0];
    };

    return (
        <div className="flex items-center gap-3 px-4 py-2 bg-white/40 dark:bg-white/5 backdrop-blur-lg border border-slate-200 dark:border-white/10 rounded-xl shadow-sm">
            <div className="flex flex-col">
                <span className="text-xs text-slate-500 dark:text-white/50 font-medium">Welcome,</span>
                <span className="text-sm font-semibold text-slate-900 dark:text-white leading-tight">
                    {getDisplayName()}
                </span>
            </div>
        </div>
    );
}
