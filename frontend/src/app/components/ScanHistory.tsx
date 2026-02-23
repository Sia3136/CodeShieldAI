import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/app/components/ui/card';
import { Clock, AlertTriangle, CheckCircle, Shield, Code, FileText, Lightbulb } from 'lucide-react';
import { motion } from 'motion/react';
import { getScanHistory, ScanHistoryItem, VulnerabilityHighlight } from '@/lib/analytics-api';
import { Badge } from '@/app/components/ui/badge';

export function ScanHistory() {
    const [scans, setScans] = useState<ScanHistoryItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const response = await getScanHistory(20);
                setScans(response.scans);
            } catch (error) {
                console.error('Failed to fetch scan history:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchHistory();
        const interval = setInterval(fetchHistory, 30000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
            case 'high':
                return 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800';
            case 'medium':
                return 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
            default:
                return 'text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
        }
    };

    const formatPreciseDate = (dateString: string) => {
        if (!dateString) return { relativeTime: '', fullDate: '' };
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return { relativeTime: '', fullDate: 'Invalid Date' };
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        // Show relative time for recent scans
        let relativeTime = '';
        if (diffMins < 1) {
            relativeTime = 'Just now';
        } else if (diffMins < 60) {
            relativeTime = `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
        } else if (diffHours < 24) {
            relativeTime = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        } else if (diffDays < 7) {
            relativeTime = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        }

        // Full precise timestamp
        const fullDate = date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });

        return { relativeTime, fullDate };
    };

    const extractLineNumbers = (highlights: string | VulnerabilityHighlight[] | undefined) => {
        if (!highlights) return null;
        if (Array.isArray(highlights)) {
            const lines = highlights.map(h => h.line).sort((a, b) => a - b);
            if (lines.length === 0) return null;
            if (lines.length === 1) return `Line ${lines[0]}`;
            return `Lines ${lines.join(', ')}`;
        }
        // Extract line numbers from highlights string
        const lineMatches = highlights.match(/line[s]?\s*(\d+)(?:\s*-\s*(\d+))?/gi);
        if (lineMatches && lineMatches.length > 0) {
            return lineMatches.map(match => {
                const nums = match.match(/\d+/g);
                if (nums && nums.length === 2) {
                    return `Lines ${nums[0]}-${nums[1]}`;
                } else if (nums && nums.length === 1) {
                    return `Line ${nums[0]}`;
                }
                return match;
            }).join(', ');
        }
        return null;
    };

    return (
        <Card className="bg-white dark:bg-slate-900 border-slate-200 dark:border-white/10">
            <CardHeader>
                <CardTitle className="flex items-center gap-2 text-slate-900 dark:text-white">
                    <Clock className="w-5 h-5" />
                    Scan History
                </CardTitle>
                <p className="text-sm text-slate-500 dark:text-white/50 mt-1">
                    Detailed vulnerability scan results with timestamps and recommendations
                </p>
            </CardHeader>
            <CardContent>
                <div className="space-y-4 max-h-[700px] overflow-y-auto">
                    {scans.length === 0 ? (
                        <div className="text-center py-12 text-slate-500 dark:text-white/50">
                            <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                            <p className="font-medium">No scans found</p>
                            <p className="text-sm mt-1">Start scanning code to see history here</p>
                        </div>
                    ) : (
                        scans.map((scan, index) => {
                            const { relativeTime, fullDate } = formatPreciseDate(scan.scan_time);
                            const lineNumbers = extractLineNumbers(scan.highlights);
                            const isExpanded = expandedIndex === index;

                            return (
                                <motion.div
                                    key={index}
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ duration: 0.3, delay: index * 0.03 }}
                                    className="border border-slate-200 dark:border-white/10 rounded-lg overflow-hidden hover:shadow-lg transition-all"
                                >
                                    {/* Header */}
                                    <div
                                        className="p-4 bg-slate-50 dark:bg-white/5 cursor-pointer hover:bg-slate-100 dark:hover:bg-white/10 transition-colors"
                                        onClick={() => setExpandedIndex(isExpanded ? null : index)}
                                    >
                                        <div className="flex items-start justify-between gap-4">
                                            <div className="flex-1 min-w-0">
                                                {/* Status and Severity */}
                                                <div className="flex items-center gap-2 mb-2 flex-wrap">
                                                    {scan.vulnerable ? (
                                                        <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0" />
                                                    ) : (
                                                        <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0" />
                                                    )}
                                                    <span className="font-semibold text-slate-900 dark:text-white">
                                                        {scan.vulnerable ? 'Vulnerability Detected' : 'Scan Passed'}
                                                    </span>
                                                    <span className={`px-3 py-1 rounded-full text-xs font-bold border ${getSeverityColor(scan.severity || 'LOW')}`}>
                                                        {(scan.severity || 'LOW').toUpperCase()}
                                                    </span>
                                                </div>

                                                {/* Timestamp */}
                                                <div className="flex items-center gap-4 text-sm text-slate-600 dark:text-white/60 mb-2">
                                                    <span className="flex items-center gap-1.5 font-medium">
                                                        <Clock className="w-4 h-4" />
                                                        {scan.scan_time ? (relativeTime || fullDate) : 'Unknown time'}
                                                    </span>
                                                    {lineNumbers && (
                                                        <span className="flex items-center gap-1.5">
                                                            <FileText className="w-4 h-4" />
                                                            {lineNumbers}
                                                        </span>
                                                    )}
                                                </div>

                                                {/* Full timestamp on hover */}
                                                {relativeTime && (
                                                    <div className="text-xs text-slate-500 dark:text-white/40">
                                                        {fullDate}
                                                    </div>
                                                )}
                                            </div>

                                            {/* Risk Score */}
                                            <div className="flex-shrink-0 text-center">
                                                <div className={`text-3xl font-bold ${scan.risk_score >= 75 ? 'text-red-600 dark:text-red-400' :
                                                    scan.risk_score >= 50 ? 'text-orange-600 dark:text-orange-400' :
                                                        scan.risk_score >= 25 ? 'text-yellow-600 dark:text-yellow-400' :
                                                            'text-green-600 dark:text-green-400'
                                                    }`}>
                                                    {(scan.risk_score ?? 0).toFixed(1)}
                                                </div>
                                                <div className="text-xs text-slate-500 dark:text-white/50 font-medium">
                                                    Risk Score
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Expanded Details */}
                                    {isExpanded && (
                                        <motion.div
                                            initial={{ height: 0, opacity: 0 }}
                                            animate={{ height: 'auto', opacity: 1 }}
                                            exit={{ height: 0, opacity: 0 }}
                                            className="border-t border-slate-200 dark:border-white/10"
                                        >
                                            <div className="p-4 space-y-4">
                                                {/* Code Snippet */}
                                                {scan.code_snippet && (
                                                    <div>
                                                        <div className="flex items-center gap-2 mb-2">
                                                            <Code className="w-4 h-4 text-slate-600 dark:text-white/60" />
                                                            <span className="text-sm font-semibold text-slate-700 dark:text-white/70">
                                                                Code Snippet
                                                            </span>
                                                        </div>
                                                        <div className="bg-slate-900 dark:bg-black/50 p-3 rounded-lg border border-slate-700 dark:border-white/20">
                                                            <pre className="text-xs text-slate-300 dark:text-white/80 font-mono overflow-x-auto">
                                                                {scan.code_snippet}
                                                            </pre>
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Vulnerability Details */}
                                                {scan.highlights && (
                                                    <div>
                                                        <div className="flex items-center gap-2 mb-2">
                                                            <AlertTriangle className="w-4 h-4 text-orange-600 dark:text-orange-400" />
                                                            <span className="text-sm font-semibold text-slate-700 dark:text-white/70">
                                                                Vulnerability Details
                                                            </span>
                                                        </div>
                                                        <div className="space-y-2">
                                                            {Array.isArray(scan.highlights) ? (
                                                                scan.highlights.map((vuln, vIdx) => (
                                                                    <div
                                                                        key={vIdx}
                                                                        className={`p-3 rounded-lg border flex flex-col gap-1 ${vuln.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30' :
                                                                            vuln.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30' :
                                                                                vuln.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/30' :
                                                                                    'bg-blue-500/10 border-blue-500/30'
                                                                            }`}
                                                                    >
                                                                        <div className="flex items-center gap-2">
                                                                            <Badge className={`${vuln.severity === 'CRITICAL' ? 'bg-red-500' :
                                                                                vuln.severity === 'HIGH' ? 'bg-orange-500' :
                                                                                    vuln.severity === 'MEDIUM' ? 'bg-yellow-500 text-black' :
                                                                                        'bg-blue-500'
                                                                                } text-white border-0 text-[10px] px-2 h-4 rounded-full flex items-center justify-center`}>
                                                                                {vuln.severity}
                                                                            </Badge>
                                                                            <span className="text-xs font-bold text-slate-900 dark:text-white">Line {vuln.line}: {vuln.type}</span>
                                                                        </div>
                                                                        <div className="text-xs font-mono bg-black/20 p-2 rounded text-slate-700 dark:text-slate-300">
                                                                            {vuln.content}
                                                                        </div>
                                                                        <div className="text-xs text-slate-600 dark:text-slate-400">
                                                                            {vuln.description}
                                                                        </div>
                                                                    </div>
                                                                ))
                                                            ) : (
                                                                <div className="bg-orange-50 dark:bg-orange-900/20 p-3 rounded-lg border border-orange-200 dark:border-orange-800 text-sm text-slate-700 dark:text-white/80">
                                                                    {scan.highlights}
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* Recommended Fix */}
                                                {scan.suggested_fix && (
                                                    <div>
                                                        <div className="flex items-center gap-2 mb-2">
                                                            <Lightbulb className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                                                            <span className="text-sm font-semibold text-slate-700 dark:text-white/70">
                                                                Recommended Fix
                                                            </span>
                                                        </div>
                                                        <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg border border-blue-200 dark:border-blue-800">
                                                            <p className="text-sm text-slate-700 dark:text-white/80">
                                                                {scan.suggested_fix}
                                                            </p>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </motion.div>
                                    )}
                                </motion.div>
                            );
                        })
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
