import React from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity, LayoutDashboard, Search, Settings, User } from 'lucide-react';

function App() {
    return (
        <div className="min-h-screen bg-slate-950 text-white font-sans">
            {/* Sidebar */}
            <div className="fixed left-0 top-0 h-full w-64 bg-slate-900 border-r border-slate-800 p-6 flex flex-col gap-8">
                <div className="flex items-center gap-3">
                    <Shield className="w-8 h-8 text-blue-500" />
                    <h1 className="text-xl font-bold tracking-tight">CodeShieldAI</h1>
                </div>

                <nav className="flex flex-col gap-2">
                    <NavItem icon={<LayoutDashboard size={20} />} label="Dashboard" active />
                    <NavItem icon={<Search size={20} />} label="Vulnerability Scan" />
                    <NavItem icon={<Activity size={20} />} label="Analytics" />
                    <NavItem icon={<User size={20} />} label="Profile" />
                    <NavItem icon={<Settings size={20} />} label="Settings" />
                </nav>
            </div>

            {/* Main Content */}
            <main className="ml-64 p-8">
                <header className="flex justify-between items-center mb-10">
                    <div>
                        <h2 className="text-3xl font-bold mb-1">Security Dashboard</h2>
                        <p className="text-slate-400">Welcome back, Siya. Here's your current security posture.</p>
                    </div>
                    <div className="bg-slate-900 p-3 rounded-full border border-slate-800">
                        <User className="w-6 h-6 text-slate-400" />
                    </div>
                </header>

                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
                    <StatCard title="Total Scans" value="42" icon={<Activity className="text-blue-500" />} />
                    <StatCard title="Open Vulnerabilities" value="7" icon={<AlertTriangle className="text-amber-500" />} />
                    <StatCard title="Critical Risks" value="2" icon={<Shield className="text-rose-500" />} />
                    <StatCard title="Fixed Issues" value="128" icon={<CheckCircle className="text-emerald-500" />} />
                </div>

                {/* Recent Activity Section */}
                <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
                    <h3 className="text-xl font-semibold mb-6">Recent Vulnerabilities</h3>
                    <div className="space-y-4">
                        <VulnerabilityItem
                            id="VULN-2026-001"
                            type="SQL Injection"
                            severity="Critical"
                            date="Feb 06, 2026"
                        />
                        <VulnerabilityItem
                            id="VULN-2026-002"
                            type="Cross-Site Scripting"
                            severity="High"
                            date="Feb 05, 2026"
                        />
                        <VulnerabilityItem
                            id="VULN-2026-003"
                            type="Broken Authentication"
                            severity="Medium"
                            date="Feb 04, 2026"
                        />
                    </div>
                </div>
            </main>
        </div>
    );
}

function NavItem({ icon, label, active = false }: { icon: React.ReactNode, label: string, active?: boolean }) {
    return (
        <div className={`flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition-colors ${active ? 'bg-blue-600 text-white' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}>
            {icon}
            <span className="font-medium">{label}</span>
        </div>
    );
}

function StatCard({ title, value, icon }: { title: string, value: string, icon: React.ReactNode }) {
    return (
        <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors">
            <div className="flex justify-between items-start mb-4">
                <span className="text-slate-400 font-medium">{title}</span>
                <div className="p-2 bg-slate-950 rounded-lg">{icon}</div>
            </div>
            <div className="text-3xl font-bold">{value}</div>
        </div>
    );
}

function VulnerabilityItem({ id, type, severity, date }: { id: string, type: string, severity: 'Critical' | 'High' | 'Medium' | 'Low', date: string }) {
    const severityColors = {
        Critical: 'text-rose-500 bg-rose-500/10',
        High: 'text-orange-500 bg-orange-500/10',
        Medium: 'text-amber-500 bg-amber-500/10',
        Low: 'text-emerald-500 bg-emerald-500/10'
    };

    return (
        <div className="flex items-center justify-between p-4 bg-slate-950 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors">
            <div className="flex flex-col gap-1">
                <span className="text-sm text-slate-500 font-mono">{id}</span>
                <span className="font-semibold">{type}</span>
            </div>
            <div className="flex items-center gap-8">
                <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${severityColors[severity]}`}>
                    {severity}
                </span>
                <span className="text-slate-500 text-sm whitespace-nowrap">{date}</span>
            </div>
        </div>
    );
}

export default App;
