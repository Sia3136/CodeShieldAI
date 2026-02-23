import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/app/components/ui/card';
import { Activity, TrendingUp, Users, AlertTriangle } from 'lucide-react';
import { motion } from 'motion/react';
import { getAnalyticsMetrics, type AnalyticsMetrics } from '@/lib/analytics-api';
import { toast } from 'sonner';

export function AnalyticsDashboard() {
    const [metrics, setMetrics] = useState<AnalyticsMetrics | null>(null);
    const [loading, setLoading] = useState(true);

    const fetchMetrics = async () => {
        try {
            const data = await getAnalyticsMetrics();
            setMetrics(data);
            setLoading(false);
        } catch (error) {
            console.error('Failed to fetch analytics:', error);
            toast.error('Failed to load analytics data');
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchMetrics();

        // Auto-refresh every 30 seconds
        const interval = setInterval(fetchMetrics, 30000);
        return () => clearInterval(interval);
    }, []);

    const stats = [
        {
            title: 'Scans Today',
            value: metrics?.scans_today || 0,
            icon: Activity,
            gradient: 'from-blue-500 to-cyan-500',
            description: 'Total scans performed in last 24 hours',
        },
        {
            title: 'Vulnerabilities Detected',
            value: metrics?.high_medium_vulnerabilities || 0,
            icon: AlertTriangle,
            gradient: 'from-orange-500 to-red-500',
            description: 'High & medium severity issues found',
        },
        {
            title: 'Active Users (7d)',
            value: metrics?.active_users_7d || 0,
            icon: Users,
            gradient: 'from-purple-500 to-pink-500',
            description: 'Unique users in the last week',
        },
    ];

    return (
        <div className="space-y-6">
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
            >
                <Card className="bg-white/40 dark:bg-white/5 backdrop-blur-lg border-slate-200 dark:border-white/10 shadow-2xl">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-2xl text-slate-900 dark:text-white">
                            <div className="p-2 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg">
                                <TrendingUp className="w-6 h-6 text-white" />
                            </div>
                            Real-Time Analytics
                        </CardTitle>
                        <CardDescription className="text-slate-600 dark:text-white/60">
                            Live metrics from MongoDB Atlas
                            {metrics && (
                                <span className="ml-2 text-xs">
                                    • Last updated: {new Date(metrics.last_updated).toLocaleTimeString()}
                                </span>
                            )}
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="grid gap-6 md:grid-cols-3">
                            {stats.map((stat, index) => (
                                <motion.div
                                    key={stat.title}
                                    initial={{ opacity: 0, scale: 0.9 }}
                                    animate={{ opacity: 1, scale: 1 }}
                                    transition={{ duration: 0.3, delay: index * 0.1 }}
                                    whileHover={{ scale: 1.05 }}
                                    className="group relative"
                                >
                                    <div className="relative p-6 bg-slate-100/50 dark:bg-black/40 backdrop-blur-sm rounded-lg border border-slate-300 dark:border-white/10 hover:border-slate-400 dark:hover:border-white/20 transition-all duration-300">
                                        {/* Gradient background on hover */}
                                        <div className={`absolute inset-0 bg-gradient-to-br ${stat.gradient} opacity-0 group-hover:opacity-10 rounded-lg transition-opacity duration-300`} />

                                        <div className="relative">
                                            {/* Icon */}
                                            <div className={`inline-block p-3 bg-gradient-to-br ${stat.gradient} rounded-lg mb-4`}>
                                                <stat.icon className="w-6 h-6 text-white" />
                                            </div>

                                            {/* Value */}
                                            <div className="mb-2">
                                                {loading ? (
                                                    <div className="h-12 w-24 bg-slate-300 dark:bg-white/10 rounded animate-pulse" />
                                                ) : (
                                                    <motion.div
                                                        className={`text-4xl font-bold bg-gradient-to-r ${stat.gradient} bg-clip-text text-transparent`}
                                                        initial={{ opacity: 0, y: 10 }}
                                                        animate={{ opacity: 1, y: 0 }}
                                                        transition={{ duration: 0.5 }}
                                                    >
                                                        {stat.value.toLocaleString()}
                                                    </motion.div>
                                                )}
                                            </div>

                                            {/* Title & Description */}
                                            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">
                                                {stat.title}
                                            </h3>
                                            <p className="text-sm text-slate-600 dark:text-white/60">
                                                {stat.description}
                                            </p>
                                        </div>
                                    </div>
                                </motion.div>
                            ))}
                        </div>

                        {/* Auto-refresh indicator */}
                        <div className="mt-6 flex items-center justify-center gap-2 text-xs text-slate-500 dark:text-white/40">
                            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                            <span>Auto-refreshing every 30 seconds</span>
                        </div>
                    </CardContent>
                </Card>
            </motion.div>
        </div>
    );
}
