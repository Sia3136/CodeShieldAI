import React, { useState, useEffect } from "react";
import { Shield, BarChart3, Code2, Github, History, Home, LogOut, User, Menu, X } from "lucide-react";
import { Button } from "./components/ui/button";
import { ThemeProvider } from "./components/ThemeProvider";
import { VulnerabilityScanner } from "./components/VulnerabilityScanner";
import { EnhancedAnalyticsDashboard } from "./components/EnhancedAnalyticsDashboard";
import { CodeViewer } from "./components/CodeViewer";
import { RepositoryScanner } from "./components/RepositoryScanner";
import { UserProfileButton } from "./components/UserProfileButton";
import { ScanHistory } from "./components/ScanHistory";
import { getToken, getCurrentUser, removeToken, type User as UserType } from "@/lib/auth-api";

interface DashboardViewProps {
    activeTab: string;
    setActiveTab: (tab: string) => void;
    setShowLanding: (show: boolean) => void;
    setShowAccount: (show: boolean) => void;
}

export function DashboardView({ activeTab, setActiveTab, setShowLanding, setShowAccount }: DashboardViewProps) {
    const [user, setUser] = useState<UserType | null>(null);
    const [sidebarOpen, setSidebarOpen] = useState(true);

    useEffect(() => {
        const fetchUser = async () => {
            const token = getToken();
            if (token) {
                try {
                    const userData = await getCurrentUser(token);
                    setUser(userData);
                } catch (error) {
                    console.error('Failed to fetch user:', error);
                }
            }
        };
        fetchUser();
    }, []);

    const handleLogout = () => {
        removeToken();
        setShowLanding(true);
    };

    return (
        <ThemeProvider>
            <div className="min-h-screen bg-[#0B0F1A] text-white transition-colors duration-500" style={{ fontFamily: 'Inter, Roboto, sans-serif' }}>

                {/* Header */}
                <header className="relative border-b border-white/10 bg-[#121826] backdrop-blur-xl">
                    <div className="container mx-auto px-2 sm:px-4 py-4">
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2 sm:gap-4">
                                <button
                                    onClick={() => setSidebarOpen(!sidebarOpen)}
                                    className="p-2 hover:bg-white/5 rounded-lg transition-colors"
                                    style={{ boxShadow: '0 0 10px rgba(59, 130, 246, 0.3)' }}
                                >
                                    <Menu className="w-6 h-6" />
                                </button>
                                <div className="flex flex-col gap-0.5">
                                    <h1 className="font-bold text-white" style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em' }}>CodeShieldAI</h1>
                                    <h2 className="text-xs text-transparent bg-clip-text bg-gradient-to-r from-[#2563EB] to-[#22D3EE]">
                                        AI-Powered Vulnerability Detection & Alert System
                                    </h2>
                                </div>
                            </div>

                            <div className="flex items-center gap-2 sm:gap-4">
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => setShowLanding(true)}
                                    className="rounded-full w-11 h-11 bg-slate-200/50 dark:bg-white/5 border-slate-300 dark:border-white/10 text-slate-900 dark:text-white hover:bg-slate-300/50 dark:hover:bg-white/10"
                                >
                                    <Home className="w-6 h-6" />
                                </Button>
                                <UserProfileButton
                                    onLogout={handleLogout}
                                    onViewAccount={() => setShowAccount(true)}
                                />
                            </div>
                        </div>
                    </div>
                </header>

                {/* Main Content with Sidebar */}
                <div className="flex">
                    {/* Left Sidebar */}
                    <aside className={`${sidebarOpen ? 'w-72' : 'w-0'} transition-all duration-300 border-r border-white/10 bg-[#121826] min-h-[calc(100vh-100px)] overflow-hidden flex flex-col`}>
                        <nav className="p-4 space-y-2 flex-1">
                            <button
                                onClick={() => setActiveTab('scanner')}
                                className={`flex items-center gap-3 justify-start px-4 py-3 text-white/70 hover:text-white hover:bg-white/5 transition-all duration-300 rounded-lg w-full ${activeTab === 'scanner' ? 'bg-blue-500/20 text-white' : ''
                                    }`}
                                style={{ fontSize: '13px', fontWeight: 500 }}
                            >
                                <Shield className="w-5 h-5" />
                                <span>Scanner</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('dashboard')}
                                className={`flex items-center gap-3 justify-start px-4 py-3 text-white/70 hover:text-white hover:bg-white/5 transition-all duration-300 rounded-lg w-full ${activeTab === 'dashboard' ? 'bg-blue-500/20 text-white' : ''
                                    }`}
                                style={{ fontSize: '13px', fontWeight: 500 }}
                            >
                                <BarChart3 className="w-5 h-5" style={{ filter: 'drop-shadow(0 0 4px rgba(147, 51, 234, 0.6))' }} />
                                <span>Dashboard</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('examples')}
                                className={`flex items-center gap-3 justify-start px-4 py-3 text-white/70 hover:text-white hover:bg-white/5 transition-all duration-300 rounded-lg w-full ${activeTab === 'examples' ? 'bg-blue-500/20 text-white' : ''
                                    }`}
                                style={{ fontSize: '13px', fontWeight: 500 }}
                            >
                                <Code2 className="w-5 h-5" />
                                <span>Examples</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('repository')}
                                className={`flex items-center gap-3 justify-start px-4 py-3 text-white/70 hover:text-white hover:bg-white/5 transition-all duration-300 rounded-lg w-full ${activeTab === 'repository' ? 'bg-blue-500/20 text-white' : ''
                                    }`}
                                style={{ fontSize: '13px', fontWeight: 500 }}
                            >
                                <Github className="w-5 h-5" />
                                <span>GitHub</span>
                            </button>
                            <button
                                onClick={() => setActiveTab('history')}
                                className={`flex items-center gap-3 justify-start px-4 py-3 text-white/70 hover:text-white hover:bg-white/5 transition-all duration-300 rounded-lg w-full ${activeTab === 'history' ? 'bg-blue-500/20 text-white' : ''
                                    }`}
                                style={{ fontSize: '13px', fontWeight: 500 }}
                            >
                                <History className="w-5 h-5" />
                                <span>History</span>
                            </button>

                            <div className="pt-4 mt-4 border-t border-white/10">
                                <button
                                    onClick={handleLogout}
                                    className="flex items-center gap-3 w-full px-4 py-3 text-sm text-red-400 hover:text-red-300 hover:bg-red-400/5 transition-colors rounded-lg"
                                >
                                    <LogOut className="w-5 h-5" />
                                    <span>Logout</span>
                                </button>
                            </div>
                        </nav>
                    </aside>

                    {/* Main Content Area */}
                    <main className="flex-1 container mx-auto px-4 py-12 bg-[#0B0F1A]">
                        {activeTab === 'scanner' && <VulnerabilityScanner />}
                        {activeTab === 'dashboard' && <EnhancedAnalyticsDashboard />}
                        {activeTab === 'examples' && <CodeViewer />}
                        {activeTab === 'repository' && <RepositoryScanner />}
                        {activeTab === 'history' && <ScanHistory />}
                    </main>
                </div>

                {/* Footer */}
                <footer className="relative border-t border-slate-200 dark:border-white/10 bg-white/60 dark:bg-black/20 backdrop-blur-lg mt-12">
                    <div className="container mx-auto px-4 py-8">
                        <div className="flex items-center justify-center">
                            <p className="text-sm text-slate-600 dark:text-white/60">
                                © 2026 CodeShieldAI. All rights reserved.
                            </p>
                        </div>
                    </div>
                </footer>
            </div>
        </ThemeProvider>
    );
}
