import React, { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/app/components/ui/card';
import { Badge } from '@/app/components/ui/badge';
import {
    Clock, AlertTriangle, CheckCircle, Shield, Code, FileText,
    Lightbulb, Github, Upload, ClipboardList, FolderGit2,
    FileCode, AlertCircle
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { getScanHistory, type ScanHistoryItem, type VulnerabilityHighlight, type ScanType } from '@/lib/analytics-api';

export function ScanHistory() {
    const [scans, setScans] = useState<ScanHistoryItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const response = await getScanHistory(30);
                setScans(response.scans);
            } catch (error) {
                console.error('Failed to fetch scan history:', error);
                setScans([]);
            } finally {
                setLoading(false);
            }
        };

        fetchHistory();
        const interval = setInterval(fetchHistory, 30000);
        return () => clearInterval(interval);
    }, []);

    // ── Helpers ────────────────────────────────────────────────────────────────

    const getSeverityColor = (severity: string = 'LOW') => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
            case 'high': return 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800';
            case 'medium': return 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
            default: return 'text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
        }
    };

    const getRiskScoreColor = (score: number) => {
        if (score >= 70) return 'text-red-600 dark:text-red-400';
        if (score >= 50) return 'text-orange-600 dark:text-orange-400';
        if (score >= 30) return 'text-yellow-600 dark:text-yellow-400';
        return 'text-green-600 dark:text-green-400';
    };

    const formatPreciseDate = (dateString: string) => {
        if (!dateString) return { relativeTime: '', fullDate: '' };
        
        // Backend datetime.utcnow().isoformat() lacks 'Z'. Add it to parse as UTC properly.
        const isoString = dateString.endsWith('Z') ? dateString : `${dateString}Z`;
        const date = new Date(isoString);
        
        if (isNaN(date.getTime())) return { relativeTime: '', fullDate: 'Invalid Date' };
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        let relativeTime = '';
        if (diffMins < 1) relativeTime = 'Just now';
        else if (diffMins < 60) relativeTime = `${diffMins}m ago`;
        else if (diffHours < 24) relativeTime = `${diffHours}h ago`;
        else if (diffDays < 7) relativeTime = `${diffDays}d ago`;

        const fullDate = date.toLocaleString('en-US', {
            timeZone: 'Asia/Kolkata',
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
        }) + ' IST';

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
        const lineMatches = (highlights as string).match(/lines?\s*(\d+)(?:\s*-\s*(\d+))?/gi);
        if (lineMatches) {
            return lineMatches.map(match => {
                const nums = match.match(/\d+/g);
                return nums?.length === 2 ? `Lines ${nums[0]}-${nums[1]}` : nums?.length === 1 ? `Line ${nums[0]}` : match;
            }).join(', ');
        }
        return null;
    };

    /** Visual badge for each scan type */
    const ScanTypeBadge = ({ type }: { type: ScanType }) => {
        switch (type) {
            case 'github':
                return (
                    <Badge className="flex items-center gap-1 bg-slate-800 dark:bg-slate-700 text-white border-0 text-[10px] px-2 py-0.5 h-5">
                        <Github className="w-3 h-3" />
                        GitHub
                    </Badge>
                );
            case 'upload':
                return (
                    <Badge className="flex items-center gap-1 bg-blue-600 text-white border-0 text-[10px] px-2 py-0.5 h-5">
                        <Upload className="w-3 h-3" />
                        Upload
                    </Badge>
                );
            case 'snippet':
            default:
                return (
                    <Badge className="flex items-center gap-1 bg-indigo-600 text-white border-0 text-[10px] px-2 py-0.5 h-5">
                        <ClipboardList className="w-3 h-3" />
                        Paste
                    </Badge>
                );
        }
    };

    // ── Render ─────────────────────────────────────────────────────────────────

    if (loading) {
        return (
            <div className="flex flex-col items-center justify-center h-64 gap-3 text-slate-500 dark:text-white/50">
                <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-500" />
                <p className="text-sm">Loading scan history…</p>
            </div>
        );
    }

    return (
        <Card className="bg-white dark:bg-slate-900 border-slate-200 dark:border-white/10">
            <CardHeader>
                <CardTitle className="flex items-center gap-2 text-slate-900 dark:text-white">
                    <Clock className="w-5 h-5" />
                    Scan History
                </CardTitle>
                <p className="text-sm text-slate-500 dark:text-white/50 mt-1">
                    All your past scans — paste, upload, and GitHub repository scans — in chronological order.
                </p>
            </CardHeader>
            <CardContent>
                <div className="space-y-3 max-h-[700px] overflow-y-auto pr-1">
                    {/* ── Empty State ── */}
                    {scans.length === 0 ? (
                        <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="text-center py-16 text-slate-500 dark:text-white/40"
                        >
                            <Shield className="w-14 h-14 mx-auto mb-4 opacity-30" />
                            <p className="text-base font-semibold text-slate-700 dark:text-white/60">
                                No scan history available.
                            </p>
                            <p className="text-sm mt-1.5">
                                Start your first scan to see results here.
                            </p>
                        </motion.div>
                    ) : (
                        scans.map((scan, index) => {
                            const { relativeTime, fullDate } = formatPreciseDate(scan.scan_time);
                            const lineNumbers = extractLineNumbers(scan.highlights);
                            const isExpanded = expandedIndex === index;
                            const isGitHub = scan.scan_type === 'github';

                            return (
                                <motion.div
                                    key={`${scan.scan_type}-${index}`}
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ duration: 0.25, delay: index * 0.03 }}
                                    className="border border-slate-200 dark:border-white/10 rounded-xl overflow-hidden hover:shadow-lg transition-all"
                                >
                                    {/* ── Header ── */}
                                    <div
                                        className={`p-4 cursor-pointer transition-colors ${isGitHub
                                                ? 'bg-slate-100 dark:bg-white/5 hover:bg-slate-200 dark:hover:bg-white/10'
                                                : 'bg-slate-50 dark:bg-white/3 hover:bg-slate-100 dark:hover:bg-white/8'
                                            }`}
                                        onClick={() => setExpandedIndex(isExpanded ? null : index)}
                                    >
                                        <div className="flex items-start justify-between gap-4">
                                            <div className="flex-1 min-w-0">
                                                {/* Row 1: status icon + title + badges */}
                                                <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                                                    {scan.vulnerable ? (
                                                        <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
                                                    ) : (
                                                        <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                                                    )}
                                                    <span className="font-semibold text-slate-900 dark:text-white text-sm">
                                                        {scan.vulnerable ? 'Vulnerability Detected' : 'Scan Passed'}
                                                    </span>
                                                    <ScanTypeBadge type={scan.scan_type || 'snippet'} />
                                                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getSeverityColor(scan.severity)}`}>
                                                        {(scan.severity || 'LOW').toUpperCase()}
                                                    </span>
                                                </div>

                                                {/* Row 2: Target (filename or repo+branch) */}
                                                <div className="flex items-center gap-1.5 text-xs text-slate-600 dark:text-white/60 mb-1 font-mono truncate">
                                                    {isGitHub ? (
                                                        <FolderGit2 className="w-3.5 h-3.5 flex-shrink-0" />
                                                    ) : (
                                                        <FileCode className="w-3.5 h-3.5 flex-shrink-0" />
                                                    )}
                                                    <span className="truncate">
                                                        {scan.target || scan.filename || 'pasted code'}
                                                        {isGitHub && scan.branch ? ` @ ${scan.branch}` : ''}
                                                    </span>
                                                </div>

                                                {/* Row 3: Timestamp + line numbers */}
                                                <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-white/40">
                                                    <span className="flex items-center gap-1">
                                                        <Clock className="w-3.5 h-3.5" />
                                                        {scan.scan_time ? (relativeTime || fullDate) : 'Unknown time'}
                                                    </span>
                                                    {relativeTime && (
                                                        <span className="hidden sm:block">{fullDate}</span>
                                                    )}
                                                    {!isGitHub && lineNumbers && (
                                                        <span className="flex items-center gap-1">
                                                            <FileText className="w-3.5 h-3.5" />
                                                            {lineNumbers}
                                                        </span>
                                                    )}
                                                    {isGitHub && (
                                                        <span className="flex items-center gap-1">
                                                            <FileCode className="w-3.5 h-3.5" />
                                                            {scan.scanned_files ?? 0} files scanned,&nbsp;
                                                            <span className={scan.vulnerable_files ? 'text-red-500' : 'text-green-500'}>
                                                                {scan.vulnerable_files ?? 0} vulnerable
                                                            </span>
                                                        </span>
                                                    )}
                                                </div>
                                            </div>

                                            {/* Risk Score */}
                                            <div className="flex-shrink-0 text-right">
                                                <div className={`text-3xl font-bold tabular-nums ${getRiskScoreColor(scan.risk_score ?? 0)}`}>
                                                    {(scan.risk_score ?? 0).toFixed(1)}
                                                </div>
                                                <div className="text-[10px] text-slate-500 dark:text-white/40 font-medium uppercase tracking-wider">
                                                    Risk Score
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* ── Expanded Details ── */}
                                    <AnimatePresence>
                                        {isExpanded && (
                                            <motion.div
                                                key="details"
                                                initial={{ height: 0, opacity: 0 }}
                                                animate={{ height: 'auto', opacity: 1 }}
                                                exit={{ height: 0, opacity: 0 }}
                                                transition={{ duration: 0.25 }}
                                                className="overflow-hidden border-t border-slate-200 dark:border-white/10"
                                            >
                                                <div className="p-4 space-y-4">
                                                    {/* GitHub scan — show file summary */}
                                                    {isGitHub && (
                                                        <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-100 dark:bg-white/5 border border-slate-200 dark:border-white/10">
                                                            <Github className="w-5 h-5 text-slate-500 dark:text-white/50 flex-shrink-0 mt-0.5" />
                                                            <div className="space-y-0.5 text-sm text-slate-700 dark:text-white/70">
                                                                <div><span className="font-semibold text-slate-900 dark:text-white">Repository:</span> {scan.target}</div>
                                                                {scan.branch && <div><span className="font-semibold text-slate-900 dark:text-white">Branch:</span> {scan.branch}</div>}
                                                                <div><span className="font-semibold text-slate-900 dark:text-white">Files scanned:</span> {scan.scanned_files ?? '—'}</div>
                                                                <div>
                                                                    <span className="font-semibold text-slate-900 dark:text-white">Vulnerable files:</span>{' '}
                                                                    <span className={(scan.vulnerable_files ?? 0) > 0 ? 'text-red-500' : 'text-green-500'}>
                                                                        {scan.vulnerable_files ?? 0}
                                                                    </span>
                                                                </div>
                                                                {scan.scan_id && (
                                                                    <div className="font-mono text-xs text-slate-400 dark:text-white/30 break-all">
                                                                        scan_id: {scan.scan_id}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Code Snippet (snippet/upload scans only) */}
                                                    {!isGitHub && scan.code_snippet && (
                                                        <div>
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <Code className="w-4 h-4 text-slate-600 dark:text-white/60" />
                                                                <span className="text-sm font-semibold text-slate-700 dark:text-white/70">Code Snippet</span>
                                                            </div>
                                                            <div className="bg-slate-900 dark:bg-black/50 p-3 rounded-lg border border-slate-700 dark:border-white/20">
                                                                <pre className="text-xs text-slate-300 dark:text-white/80 font-mono overflow-x-auto whitespace-pre-wrap">
                                                                    {scan.code_snippet.slice(0, 800)}
                                                                    {scan.code_snippet.length > 800 ? '\n… (truncated)' : ''}
                                                                </pre>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Vulnerability Highlights */}
                                                    {!isGitHub && scan.highlights && (
                                                        <div>
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <AlertTriangle className="w-4 h-4 text-orange-500" />
                                                                <span className="text-sm font-semibold text-slate-700 dark:text-white/70">Vulnerability Details</span>
                                                            </div>
                                                            <div className="space-y-2">
                                                                {Array.isArray(scan.highlights) ? (
                                                                    scan.highlights.map((vuln, vIdx) => (
                                                                        <div
                                                                            key={vIdx}
                                                                            className={`p-3 rounded-lg border text-xs flex flex-col gap-1.5 ${vuln.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30' :
                                                                                    vuln.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30' :
                                                                                        vuln.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/30' :
                                                                                            'bg-teal-500/10 border-teal-500/30'
                                                                                }`}
                                                                        >
                                                                            <div className="flex items-center gap-2">
                                                                                <Badge className={`${vuln.severity === 'CRITICAL' ? 'bg-red-500' :
                                                                                        vuln.severity === 'HIGH' ? 'bg-orange-500' :
                                                                                            vuln.severity === 'MEDIUM' ? 'bg-amber-500 text-black' :
                                                                                                'bg-teal-500'
                                                                                    } text-white border-0 text-[10px] px-1.5 h-4 rounded-full`}>
                                                                                    {vuln.severity}
                                                                                </Badge>
                                                                                <span className="font-bold text-slate-900 dark:text-white">
                                                                                    Line {vuln.line}: {vuln.type}
                                                                                </span>
                                                                            </div>
                                                                            {vuln.content && (
                                                                                <div className="font-mono bg-black/20 dark:bg-black/40 p-1.5 rounded text-slate-700 dark:text-slate-300">
                                                                                    {vuln.content}
                                                                                </div>
                                                                            )}
                                                                            {vuln.description && (
                                                                                <div className="text-slate-600 dark:text-slate-400 italic">{vuln.description}</div>
                                                                            )}
                                                                            {vuln.fix && (
                                                                                <div className="text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/20 p-2 rounded border border-blue-200 dark:border-blue-700">
                                                                                    <span className="font-semibold">Fix: </span>{vuln.fix}
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                    ))
                                                                ) : (
                                                                    <div className="bg-orange-50 dark:bg-orange-900/20 p-3 rounded-lg border border-orange-200 dark:border-orange-800 text-sm text-slate-700 dark:text-white/80">
                                                                        {scan.highlights as string}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Recommended Fix */}
                                                    {scan.suggested_fix && (
                                                        <div>
                                                            <div className="flex items-center gap-2 mb-2">
                                                                <Lightbulb className="w-4 h-4 text-blue-500" />
                                                                <span className="text-sm font-semibold text-slate-700 dark:text-white/70">Recommended Fix</span>
                                                            </div>
                                                            <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg border border-blue-200 dark:border-blue-800">
                                                                <p className="text-sm text-slate-700 dark:text-white/80 whitespace-pre-wrap">{scan.suggested_fix}</p>
                                                            </div>
                                                        </div>
                                                    )}

                                                    {/* Clean result message */}
                                                    {!scan.vulnerable && !scan.highlights && !scan.code_snippet && !isGitHub && (
                                                        <div className="flex items-center gap-2 p-3 rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-sm text-green-700 dark:text-green-300">
                                                            <CheckCircle className="w-4 h-4 flex-shrink-0" />
                                                            No security vulnerabilities were detected in this scan.
                                                        </div>
                                                    )}
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </motion.div>
                            );
                        })
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
