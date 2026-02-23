import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/app/components/ui/card';
import { Button } from '@/app/components/ui/button';
import { Input } from '@/app/components/ui/input';
import { Badge } from '@/app/components/ui/badge';
import { Progress } from '@/app/components/ui/progress';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/app/components/ui/select';
import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
} from '@/app/components/ui/accordion';
import { Alert, AlertDescription, AlertTitle } from '@/app/components/ui/alert';
import {
    Github,
    GitBranch,
    FileCode,
    Shield,
    AlertTriangle,
    CheckCircle,
    Loader2,
    ExternalLink,
    AlertCircle,
    Download,
    Eye,
    Activity,
    Clock
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { toast } from 'sonner';
import {
    scanRepository,
    getRepositoryBranches,
    getUserRepositories,
    getGitHubToken,
    type RepositoryScanResult,
    type Repository,
    type Branch
} from '@/lib/github-api';
import { GitHubAuth } from './GitHubAuth';
import type { GitHubUser } from '@/lib/github-api';
import { getToken, getCurrentUser } from '@/lib/auth-api';
import { generatePDFReport } from '@/lib/pdf-export';

export function RepositoryScanner() {
    const [user, setUser] = useState<GitHubUser | null>(null);
    const [accessToken, setAccessToken] = useState<string | null>(null);
    const [repoUrl, setRepoUrl] = useState('');
    const [selectedBranch, setSelectedBranch] = useState('main');
    const [selectedModel, setSelectedModel] = useState('GraphCodeBERT');
    const [branches, setBranches] = useState<Branch[]>([]);
    const [repositories, setRepositories] = useState<Repository[]>([]);
    const [scanning, setScanning] = useState(false);
    const [scanResult, setScanResult] = useState<RepositoryScanResult | null>(null);
    const [scanDuration, setScanDuration] = useState<number | null>(null);
    const [loadingBranches, setLoadingBranches] = useState(false);
    const [showCleanFiles, setShowCleanFiles] = useState(false);
    const [showObsForFile, setShowObsForFile] = useState<Record<number, boolean>>({});

    // Load user and token from auth context or localStorage
    useEffect(() => {
        const checkExistingAuth = async () => {
            const storedUser = localStorage.getItem('github_user');
            const storedToken = localStorage.getItem('github_token');
            const appToken = getToken();

            if (storedUser && storedToken) {
                // Priority: Use token stored in localStorage (from recent GitHub session)
                setUser(JSON.parse(storedUser));
                setAccessToken(storedToken);
            } else if (appToken) {
                // If logged in via GitHub but no token in local storage, fetch from backend
                try {
                    const appUser = await getCurrentUser(appToken);
                    if (appUser.auth_provider === 'github') {
                        const githubToken = await getGitHubToken(appToken);

                        const githubUser: GitHubUser = {
                            id: 0,
                            login: appUser.username || '',
                            name: appUser.name,
                            email: appUser.email,
                            avatar_url: appUser.avatar_url || '',
                            html_url: ''
                        };

                        setUser(githubUser);
                        setAccessToken(githubToken);

                        // Cache it for this component's lifespan and refresh
                        localStorage.setItem('github_user', JSON.stringify(githubUser));
                        localStorage.setItem('github_token', githubToken);
                    }
                } catch (e) {
                    console.error('Auto-connect check failed:', e);
                }
            }
        };
        checkExistingAuth();
    }, []);

    // Load user repositories when authenticated
    useEffect(() => {
        if (accessToken) {
            loadRepositories();
        }
    }, [accessToken]);

    const loadRepositories = async () => {
        if (!accessToken) return;

        try {
            const repos = await getUserRepositories(accessToken);
            setRepositories(repos);
        } catch (error: any) {
            console.error('Failed to load repositories:', error);
            if (error.message?.includes('401')) {
                // Token might be expired
                setAccessToken(null);
                setUser(null);
            }
        }
    };

    const loadBranches = async (repoFullName: string) => {
        if (!accessToken) return;

        setLoadingBranches(true);
        try {
            const branchList = await getRepositoryBranches(repoFullName, accessToken);
            setBranches(branchList);

            // Fetch default branch if main/master are not there
            const defaultBranch = branchList.find(b => b.name === 'main' || b.name === 'master');
            if (defaultBranch) {
                setSelectedBranch(defaultBranch.name);
            } else if (branchList.length > 0) {
                setSelectedBranch(branchList[0].name);
            }
        } catch (error: any) {
            toast.error('Failed to load branches');
            setBranches([]);
        } finally {
            setLoadingBranches(false);
        }
    };

    const handleRepoSelect = (repo: Repository) => {
        setRepoUrl(repo.clone_url);
        loadBranches(repo.full_name);
    };

    const handleScan = async () => {
        if (!repoUrl.trim()) {
            toast.error('Please enter a repository URL');
            return;
        }

        setScanning(true);
        setScanResult(null);
        setScanDuration(null);
        const startTime = Date.now();

        try {
            console.log('[SCAN] Starting repository scan...', {
                repoUrl,
                branch: selectedBranch,
                model: selectedModel
            });

            const result = await scanRepository(
                repoUrl,
                selectedBranch,
                selectedModel,
                undefined, // Use default file patterns
                accessToken || undefined,
                getToken() || undefined
            );

            console.log('[SCAN] Scan completed successfully:', result);
            console.log('[SCAN] File results count:', result.file_results?.length || 0);
            console.log('[SCAN] Vulnerable files:', result.vulnerable_files);

            setScanResult(result);
            setScanDuration((Date.now() - startTime) / 1000);
            toast.success(`Scan completed! Found ${result.vulnerable_files} vulnerable files out of ${result.scanned_files} scanned.`);
        } catch (error: any) {
            console.error('[SCAN] Scan failed:', error);
            toast.error(error.message || 'Scan failed');
        } finally {
            setScanning(false);
        }
    };

    const getSeverityColor = (severity: string) => {
        switch (severity?.toLowerCase()) {
            case 'critical':
                return 'bg-gradient-to-r from-red-500 to-rose-600';
            case 'high':
                return 'bg-gradient-to-r from-orange-500 to-amber-600';
            case 'medium':
                return 'bg-gradient-to-r from-yellow-500 to-orange-500';
            case 'low':
                return 'bg-gradient-to-r from-blue-500 to-cyan-500';
            default:
                return 'bg-gray-500';
        }
    };

    const getRiskLevel = (score: number) => {
        if (score >= 70) return { label: 'Critical', color: 'text-red-400', gradient: 'from-red-500 to-rose-600' };
        if (score >= 50) return { label: 'High', color: 'text-orange-400', gradient: 'from-orange-500 to-amber-600' };
        if (score >= 30) return { label: 'Medium', color: 'text-yellow-400', gradient: 'from-yellow-500 to-orange-500' };
        if (score > 0) return { label: 'Low', color: 'text-blue-400', gradient: 'from-blue-500 to-cyan-500' };
        return { label: 'Safe', color: 'text-emerald-400', gradient: 'from-emerald-500 to-green-500' };
    };

    // Count severity across all confirmed findings in all files
    const allConfirmedFindings = (scanResult?.file_results ?? [])
        .filter(f => f.status === 'scanned')
        .flatMap(f => (f.highlights ?? []) as any[]);

    const countSev = (sev: string) =>
        allConfirmedFindings.filter((v: any) => (v.severity ?? '').toUpperCase() === sev.toUpperCase()).length;

    return (
        <div className="space-y-6">
            {/* Authentication Card */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
            >
                <Card className="bg-white/40 dark:bg-white/5 backdrop-blur-lg border-slate-200 dark:border-white/10 shadow-2xl">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-2xl text-slate-900 dark:text-white">
                            <div className="p-2 bg-gradient-to-br from-slate-700 to-slate-900 rounded-lg">
                                <Github className="w-6 h-6 text-white" />
                            </div>
                            GitHub Repository Scanner
                        </CardTitle>
                        <CardDescription className="text-slate-600 dark:text-white/60">
                            Scan entire GitHub repositories for security vulnerabilities
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <GitHubAuth
                            onAuthChange={(newUser, newToken) => {
                                setUser(newUser);
                                setAccessToken(newToken);
                            }}
                        />
                    </CardContent>
                </Card>
            </motion.div>

            {/* Scanner Configuration */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.1 }}
            >
                <Card className="bg-white/40 dark:bg-white/5 backdrop-blur-lg border-slate-200 dark:border-white/10 shadow-2xl">
                    <CardHeader>
                        <CardTitle className="text-slate-900 dark:text-white">Scan Configuration</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        {/* Repository URL */}
                        <div className="space-y-2">
                            <label className="text-sm font-medium text-slate-700 dark:text-white/80">
                                Repository URL
                            </label>
                            <Input
                                placeholder="https://github.com/owner/repository"
                                value={repoUrl}
                                onChange={(e) => setRepoUrl(e.target.value)}
                                className="bg-slate-100 dark:bg-black/40 border-slate-300 dark:border-white/20 text-slate-900 dark:text-white"
                            />
                        </div>

                        {/* Repository Selection (if authenticated) */}
                        {user && repositories.length > 0 && (
                            <div className="space-y-2">
                                <label className="text-sm font-medium text-slate-700 dark:text-white/80">
                                    Or select from your repositories
                                </label>
                                <Select onValueChange={(value) => {
                                    const repo = repositories.find(r => r.full_name === value);
                                    if (repo) handleRepoSelect(repo);
                                }}>
                                    <SelectTrigger className="bg-slate-100 dark:bg-black/40 border-slate-300 dark:border-white/20">
                                        <SelectValue placeholder="Select a repository" />
                                    </SelectTrigger>
                                    <SelectContent className="bg-white dark:bg-slate-900 border-slate-200 dark:border-white/20">
                                        {repositories.map((repo) => (
                                            <SelectItem key={repo.id} value={repo.full_name}>
                                                <div className="flex items-center gap-2">
                                                    <FileCode className="h-4 w-4" />
                                                    <span>{repo.full_name}</span>
                                                    {repo.private && (
                                                        <Badge variant="secondary" className="text-xs">Private</Badge>
                                                    )}
                                                </div>
                                            </SelectItem>
                                        ))}
                                    </SelectContent>
                                </Select>
                            </div>
                        )}

                        {/* Branch Selection */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <label className="text-sm font-medium text-slate-700 dark:text-white/80 flex items-center gap-2">
                                    <GitBranch className="h-4 w-4" />
                                    Branch
                                </label>
                                <Select value={selectedBranch} onValueChange={setSelectedBranch}>
                                    <SelectTrigger className="bg-slate-100 dark:bg-black/40 border-slate-300 dark:border-white/20">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent className="bg-white dark:bg-slate-900 border-slate-200 dark:border-white/20">
                                        {branches.length > 0 ? (
                                            branches.map((branch) => (
                                                <SelectItem key={branch.name} value={branch.name}>
                                                    {branch.name}
                                                    {branch.protected && (
                                                        <Badge variant="secondary" className="ml-2 text-xs">Protected</Badge>
                                                    )}
                                                </SelectItem>
                                            ))
                                        ) : (
                                            <>
                                                <SelectItem value="main">main</SelectItem>
                                                <SelectItem value="master">master</SelectItem>
                                            </>
                                        )}
                                    </SelectContent>
                                </Select>
                            </div>

                            {/* Model Selection */}
                            <div className="space-y-2">
                                <label className="text-sm font-medium text-slate-700 dark:text-white/80 flex items-center gap-2">
                                    <Shield className="h-4 w-4" />
                                    AI Model
                                </label>
                                <Select value={selectedModel} onValueChange={setSelectedModel}>
                                    <SelectTrigger className="bg-slate-100 dark:bg-black/40 border-slate-300 dark:border-white/20">
                                        <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent className="bg-white dark:bg-slate-900 border-slate-200 dark:border-white/20">
                                        <SelectItem value="GraphCodeBERT">GraphCodeBERT (Recommended)</SelectItem>
                                        <SelectItem value="CodeBERT">CodeBERT</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                        </div>

                        {/* Scan Button */}
                        <Button
                            onClick={handleScan}
                            disabled={!repoUrl || scanning}
                            className="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white shadow-lg"
                        >
                            {scanning ? (
                                <>
                                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                    Scanning Repository... This may take several minutes for large repos
                                </>
                            ) : (
                                <>
                                    <Shield className="w-4 h-4 mr-2" />
                                    Scan Repository
                                </>
                            )}
                        </Button>

                        {/* Scanning Progress Message */}
                        {scanning && (
                            <motion.div
                                initial={{ opacity: 0, y: -10 }}
                                animate={{ opacity: 1, y: 0 }}
                                className="p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg"
                            >
                                <p className="text-sm text-blue-600 dark:text-blue-400 text-center">
                                    ⚡ Scanning repository with parallel processing... Large repos may take 2-3 minutes.
                                </p>
                            </motion.div>
                        )}
                    </CardContent>
                </Card>
            </motion.div>

            {/* Scan Results */}
            <AnimatePresence>
                {scanResult && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.5 }}
                        className="space-y-6"
                    >
                        {/* Summary Card */}
                        <Card className="bg-white/5 backdrop-blur-lg border-white/10 shadow-2xl overflow-hidden">
                            <div className={`h-2 bg-gradient-to-r ${getRiskLevel(scanResult.overall_risk_score).gradient}`} />
                            <CardHeader>
                                <div className="flex items-center justify-between">
                                    <div>
                                        <CardTitle className="text-slate-900 dark:text-white flex items-center gap-2">
                                            <Github className="h-5 w-5" />
                                            {scanResult.repository}
                                        </CardTitle>
                                        <CardDescription className="text-slate-600 dark:text-white/60">
                                            Scanned {scanResult.scanned_files} files on branch {scanResult.branch}
                                        </CardDescription>
                                    </div>
                                    <Button
                                        onClick={() => {
                                            try {
                                                // Convert repository scan result to PDF format
                                                const vulnerabilities = scanResult.file_results
                                                    ?.filter(f => f.highlights && Array.isArray(f.highlights) && f.highlights.length > 0)
                                                    .flatMap((file, fileIdx) =>
                                                        file.highlights?.map((vuln: any, vulnIdx: number) => ({
                                                            id: `${fileIdx}-${vulnIdx}`,
                                                            type: vuln.type || 'Security Issue',
                                                            severity: (vuln.severity?.toLowerCase() || 'medium') as 'critical' | 'high' | 'medium' | 'low',
                                                            line: vuln.line || 0,
                                                            description: `${file.file_path}: ${vuln.description || 'Vulnerability detected'}`,
                                                            recommendation: vuln.fix || vuln.recommendation || 'Manual review required',
                                                            fix: vuln.fix,
                                                            codeSnippet: vuln.content,
                                                            confidence: 95
                                                        })) || []
                                                    ) || [];

                                                const pdfData = {
                                                    riskScore: scanResult.overall_risk_score || 0,
                                                    vulnerabilities,
                                                    linesScanned: scanResult.scanned_files || 0,
                                                    timeElapsed: 0
                                                };

                                                generatePDFReport(
                                                    pdfData,
                                                    `Repository: ${scanResult.repository}\nBranch: ${scanResult.branch}\nTotal Files: ${scanResult.total_files}\nScanned Files: ${scanResult.scanned_files}`,
                                                    selectedModel
                                                );
                                                toast.success('PDF report downloaded successfully!');
                                            } catch (error) {
                                                toast.error('Failed to generate PDF report');
                                                console.error('PDF generation error:', error);
                                            }
                                        }}
                                        className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white shadow-lg"
                                    >
                                        <Download className="w-4 h-4 mr-2" />
                                        Download PDF Report
                                    </Button>
                                </div>
                            </CardHeader>
                            <CardContent className="space-y-4">
                                {/* Row 1: Primary Layer — 5 core metrics */}
                                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                    <div className="text-center p-4 bg-amber-500/10 backdrop-blur-sm rounded-xl border border-amber-500/20">
                                        <Shield className="w-5 h-5 mx-auto mb-1 text-amber-400" />
                                        <div className={`text-4xl font-bold ${getRiskLevel(scanResult.overall_risk_score || 0).color}`}>
                                            {(scanResult.overall_risk_score ?? 0).toFixed(1)}
                                        </div>
                                        <div className="text-xs text-white/50 mt-1 uppercase tracking-wider font-semibold">Risk Score</div>
                                    </div>

                                    <div className="text-center p-4 bg-blue-500/10 backdrop-blur-sm rounded-xl border border-blue-500/20">
                                        <Activity className="w-5 h-5 mx-auto mb-1 text-blue-400" />
                                        <div className="text-4xl font-bold text-blue-400">
                                            {getRiskLevel(scanResult.overall_risk_score || 0).label}
                                        </div>
                                        <div className="text-xs text-white/50 mt-1 uppercase tracking-wider font-semibold">Severity</div>
                                    </div>

                                    <div className="text-center p-4 bg-red-500/10 backdrop-blur-sm rounded-xl border border-red-500/20">
                                        <AlertTriangle className="w-5 h-5 mx-auto mb-1 text-red-400" />
                                        <div className="text-4xl font-bold text-red-400">
                                            {allConfirmedFindings.length}
                                        </div>
                                        <div className="text-xs text-white/50 mt-1 uppercase tracking-wider font-semibold">Vulnerabilities</div>
                                    </div>

                                    <div className="text-center p-4 bg-purple-500/10 backdrop-blur-sm rounded-xl border border-purple-500/20">
                                        <Clock className="w-5 h-5 mx-auto mb-1 text-purple-400" />
                                        <div className="text-4xl font-bold text-purple-300">
                                            {scanDuration ? `${scanDuration.toFixed(1)}s` : '--'}
                                        </div>
                                        <div className="text-xs text-white/50 mt-1 uppercase tracking-wider font-semibold">Scan Duration</div>
                                    </div>

                                    <div className="text-center p-4 bg-teal-500/10 backdrop-blur-sm rounded-xl border border-teal-500/20">
                                        <FileCode className="w-5 h-5 mx-auto mb-1 text-teal-400" />
                                        <div className="text-4xl font-bold text-teal-300">
                                            {scanResult.scanned_files?.toLocaleString() || '--'}
                                        </div>
                                        <div className="text-xs text-white/50 mt-1 uppercase tracking-wider font-semibold">Files Scanned</div>
                                    </div>
                                </div>

                                {/* Row 2: Secondary Inline Severity Strip */}
                                <div className="flex items-center justify-center gap-1 py-3 px-4 bg-black/40 backdrop-blur-sm rounded-lg border border-white/10 text-sm">
                                    <div className="flex items-center gap-1.5">
                                        <span className="font-bold text-red-500">Critical</span>
                                        <span className="text-white/80">{countSev('CRITICAL')}</span>
                                    </div>
                                    <span className="text-white/20 mx-2">|</span>
                                    <div className="flex items-center gap-1.5">
                                        <span className="font-bold text-orange-500">High</span>
                                        <span className="text-white/80">{countSev('HIGH')}</span>
                                    </div>
                                    <span className="text-white/20 mx-2">|</span>
                                    <div className="flex items-center gap-1.5">
                                        <span className="font-bold text-amber-500">Medium</span>
                                        <span className="text-white/80">{countSev('MEDIUM')}</span>
                                    </div>
                                    <span className="text-white/20 mx-2">|</span>
                                    <div className="flex items-center gap-1.5">
                                        <span className="font-bold text-teal-500">Low</span>
                                        <span className="text-white/80">{countSev('LOW')}</span>
                                    </div>
                                    <span className="text-white/20 mx-2">|</span>
                                </div>

                                {/* Total confirmed count */}
                                <div className="flex items-center gap-2 px-1">
                                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                                    <span className="text-sm text-white/60">
                                        <span className="font-bold text-white">{allConfirmedFindings.length}</span> confirmed findings across all files
                                    </span>
                                </div>

                                {scanResult.overall_risk_score === 0 && (
                                    <Alert className="bg-gradient-to-r from-green-500/20 to-emerald-500/20 border-green-500/30">
                                        <CheckCircle className="h-4 w-4 text-green-400" />
                                        <AlertTitle className="text-green-400">Repository is secure!</AlertTitle>
                                        <AlertDescription className="text-slate-700 dark:text-white/80">
                                            No vulnerabilities detected in this repository.
                                        </AlertDescription>
                                    </Alert>
                                )}
                            </CardContent>
                        </Card>

                        {/* File Results */}
                        {scanResult.file_results && scanResult.file_results.length > 0 && (
                            <Card className="bg-white/5 backdrop-blur-lg border-white/10 shadow-2xl">
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <CardTitle className="text-slate-900 dark:text-white">File Analysis</CardTitle>
                                    <div className="flex items-center gap-2">
                                        <label className="text-xs text-slate-500 dark:text-white/50 cursor-pointer select-none" htmlFor="show-clean">
                                            Show clean files
                                        </label>
                                        <input
                                            id="show-clean"
                                            type="checkbox"
                                            checked={showCleanFiles}
                                            onChange={(e) => setShowCleanFiles(e.target.checked)}
                                            className="w-3.5 h-3.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500 dark:border-gray-600 dark:bg-gray-700 dark:ring-offset-gray-800"
                                        />
                                    </div>
                                </CardHeader>
                                <CardContent>
                                    <Accordion type="single" collapsible className="space-y-2">
                                        {scanResult.file_results
                                            .filter(f => f.status === 'scanned')
                                            .filter(f => showCleanFiles || (f.risk_score && f.risk_score > 0) || f.vulnerable)
                                            .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
                                            .map((file, index) => (
                                                <AccordionItem
                                                    key={index}
                                                    value={`file-${index}`}
                                                    className="bg-slate-50 dark:bg-black/40 backdrop-blur-sm border border-slate-300 dark:border-white/10 rounded-lg px-4"
                                                >
                                                    <AccordionTrigger className="hover:no-underline">
                                                        <div className="flex items-center gap-3 flex-1">
                                                            <FileCode className="h-4 w-4 text-slate-600 dark:text-white/60" />
                                                            <span className="text-sm font-mono text-slate-900 dark:text-white truncate flex-1 text-left">
                                                                {file.file_path}
                                                            </span>
                                                            {file.severity && (
                                                                <Badge className={`${getSeverityColor(file.severity)} text-white border-0`}>
                                                                    {file.severity.toUpperCase()}
                                                                </Badge>
                                                            )}
                                                            {file.risk_score !== undefined && (
                                                                <span className={`text-sm font-bold ${getRiskLevel(file.risk_score).color}`}>
                                                                    {file.risk_score.toFixed(1)}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </AccordionTrigger>
                                                    <AccordionContent className="space-y-3 pt-3">
                                                        {file.highlights && file.highlights.length > 0 && (
                                                            <div className="space-y-2">
                                                                <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Confirmed Findings:</div>
                                                                {Array.isArray(file.highlights) ? (
                                                                    file.highlights.map((vuln, vIdx) => (
                                                                        <div
                                                                            key={vIdx}
                                                                            className={`p-3 rounded-lg border flex flex-col gap-1 ${vuln.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30' :
                                                                                vuln.severity === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30' :
                                                                                    vuln.severity === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/30' :
                                                                                        'bg-blue-500/10 border-blue-500/30'
                                                                                }`}
                                                                        >
                                                                            <div className="flex items-center justify-between gap-2 flex-wrap">
                                                                                <div className="flex items-center gap-2">
                                                                                    <Badge className={`${vuln.severity === 'CRITICAL' ? 'bg-red-500' :
                                                                                        vuln.severity === 'HIGH' ? 'bg-orange-500' :
                                                                                            vuln.severity === 'MEDIUM' ? 'bg-amber-500' :
                                                                                                'bg-teal-500'
                                                                                        } text-white border-0 text-[10px] px-1.5 h-4`}>
                                                                                        {vuln.severity}
                                                                                    </Badge>
                                                                                    <span className="text-xs font-bold text-slate-900 dark:text-white">Line {vuln.line}: {vuln.type}</span>
                                                                                </div>
                                                                                {/* Confidence Score */}
                                                                                <span className="flex items-center gap-1 text-[10px] font-semibold text-slate-500 dark:text-white/40 bg-white/5 px-2 py-0.5 rounded-full border border-white/10">
                                                                                    Confidence: <span className="text-emerald-400 ml-0.5">{vuln.confidence !== undefined ? `${Math.round(vuln.confidence * 100)}%` : '—'}</span>
                                                                                </span>
                                                                            </div>
                                                                            <div className="text-xs font-mono bg-black/20 p-1.5 rounded text-slate-700 dark:text-slate-300">
                                                                                {vuln.content}
                                                                            </div>
                                                                            <div className="text-xs text-slate-600 dark:text-slate-400 italic">
                                                                                {vuln.description}
                                                                            </div>
                                                                            {vuln.fix && (
                                                                                <div className="mt-2 text-[11px] bg-blue-500/5 dark:bg-blue-500/10 p-2 rounded border border-blue-500/20 text-blue-700 dark:text-blue-300">
                                                                                    <span className="font-bold">Recommendation: </span>
                                                                                    {vuln.fix}
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                    ))
                                                                ) : (
                                                                    <div className="bg-slate-200 dark:bg-black/40 p-3 rounded font-mono text-xs whitespace-pre-wrap border border-slate-300 dark:border-white/10 text-slate-900 dark:text-white/90">
                                                                        {String(file.highlights)}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        )}
                                                        {(!file.highlights || file.highlights.length === 0) && (
                                                            <div className="flex flex-col items-center justify-center py-6 text-slate-500 dark:text-white/40">
                                                                <CheckCircle className="h-8 w-8 mb-2 text-green-500/50" />
                                                                <p className="text-sm">No vulnerabilities detected in this file.</p>
                                                            </div>
                                                        )}
                                                        {file.suggested_fix && (!Array.isArray(file.highlights) || !file.highlights.some(v => v.fix)) && (
                                                            <Alert className="bg-blue-100 dark:bg-blue-500/10 border-blue-300 dark:border-blue-500/30">
                                                                <AlertCircle className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                                                                <AlertTitle className="text-blue-700 dark:text-blue-300">Recommended Fix</AlertTitle>
                                                                <AlertDescription className="text-sm text-slate-700 dark:text-white/80 whitespace-pre-wrap">
                                                                    {file.suggested_fix}
                                                                </AlertDescription>
                                                            </Alert>
                                                        )}
                                                    </AccordionContent>
                                                </AccordionItem>
                                            ))}
                                    </Accordion>
                                </CardContent>
                            </Card>
                        )}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
