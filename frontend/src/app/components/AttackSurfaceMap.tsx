import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Shield, AlertTriangle, Lock, Database, Code2, Settings, FileWarning, Eye } from 'lucide-react';

interface Vulnerability {
    name: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    example: string;
    fixAvailable: boolean;
}

interface VulnerabilityCategory {
    id: string;
    title: string;
    icon: any;
    color: string;
    gradient: string;
    position: { x: number; y: number };
    vulnerabilities: Vulnerability[];
}

export function AttackSurfaceMap() {
    const [hoveredCategory, setHoveredCategory] = useState<string | null>(null);
    const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);

    const categories: VulnerabilityCategory[] = [
        {
            id: 'injection',
            title: 'Injection Attacks',
            icon: Code2,
            color: '#EF4444',
            gradient: 'from-[#EF4444] to-[#DC2626]',
            position: { x: 20, y: 15 },
            vulnerabilities: [
                { name: 'SQL Injection', severity: 'Critical', example: 'SELECT * FROM users WHERE id = \' OR \'1\'=\'1', fixAvailable: true },
                { name: 'Command Injection', severity: 'Critical', example: 'system("ping " + userInput)', fixAvailable: true },
                { name: 'Path Traversal', severity: 'High', example: '../../../etc/passwd', fixAvailable: true },
            ],
        },
        {
            id: 'web-exploits',
            title: 'Web Exploits',
            icon: AlertTriangle,
            color: '#F97316',
            gradient: 'from-[#F97316] to-[#EA580C]',
            position: { x: 75, y: 20 },
            vulnerabilities: [
                { name: 'Cross-Site Scripting (XSS)', severity: 'High', example: '<script>alert(document.cookie)</script>', fixAvailable: true },
                { name: 'Cross-Site Request Forgery (CSRF)', severity: 'High', example: 'Forged POST request without token validation', fixAvailable: true },
                { name: 'Server-Side Request Forgery (SSRF)', severity: 'High', example: 'fetch(userControlledURL)', fixAvailable: true },
            ],
        },
        {
            id: 'access-auth',
            title: 'Access & Auth',
            icon: Lock,
            color: '#8B5CF6',
            gradient: 'from-[#8B5CF6] to-[#7C3AED]',
            position: { x: 15, y: 60 },
            vulnerabilities: [
                { name: 'Broken Authentication', severity: 'Critical', example: 'Weak password policy, no MFA', fixAvailable: true },
                { name: 'Broken Access Control', severity: 'Critical', example: 'User can access admin endpoints', fixAvailable: true },
                { name: 'Insecure Direct Object References (IDOR)', severity: 'High', example: '/user/123 accessible by any user', fixAvailable: true },
            ],
        },
        {
            id: 'config-integrity',
            title: 'Configuration & Integrity',
            icon: Settings,
            color: '#EAB308',
            gradient: 'from-[#EAB308] to-[#CA8A04]',
            position: { x: 80, y: 65 },
            vulnerabilities: [
                { name: 'Security Misconfiguration', severity: 'Medium', example: 'Default credentials, debug mode enabled', fixAvailable: true },
                { name: 'Insecure Deserialization', severity: 'High', example: 'pickle.loads(untrusted_data)', fixAvailable: true },
                { name: 'XML External Entities (XXE)', severity: 'High', example: 'Unvalidated XML parser configuration', fixAvailable: true },
            ],
        },
        {
            id: 'dependencies',
            title: 'Dependencies & Monitoring',
            icon: FileWarning,
            color: '#22D3EE',
            gradient: 'from-[#22D3EE] to-[#06B6D4]',
            position: { x: 50, y: 85 },
            vulnerabilities: [
                { name: 'Using Components with Known Vulnerabilities', severity: 'High', example: 'Outdated library with CVE-2023-XXXX', fixAvailable: true },
                { name: 'Sensitive Data Exposure', severity: 'Critical', example: 'API keys in client-side code', fixAvailable: true },
                { name: 'Insufficient Logging & Monitoring', severity: 'Medium', example: 'No audit trail for security events', fixAvailable: true },
            ],
        },
    ];

    const getSeverityColor = (severity: string) => {
        switch (severity) {
            case 'Critical': return '#EF4444';
            case 'High': return '#F97316';
            case 'Medium': return '#EAB308';
            case 'Low': return '#22D3EE';
            default: return '#6B7280';
        }
    };

    return (
        <section className="relative px-6 py-32 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#0f1a2e] to-transparent" />

            {/* Grid background */}
            <div className="absolute inset-0 bg-[linear-gradient(to_right,#1a1f35_1px,transparent_1px),linear-gradient(to_bottom,#1a1f35_1px,transparent_1px)] bg-[size:3rem_3rem] opacity-20" />

            <div className="relative z-10 max-w-7xl mx-auto">
                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.6 }}
                    className="text-center mb-20"
                >
                    <div className="inline-block px-4 py-2 rounded-full bg-[#EF4444]/10 border border-[#EF4444]/20 text-[#EF4444] text-sm mb-6">
                        Attack Surface Analysis
                    </div>
                    <h2 className="text-4xl lg:text-5xl font-bold text-white mb-6">
                        Your Entire Attack Surface,{' '}
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#EF4444] to-[#F97316]">
                            Mapped in One Scan
                        </span>
                    </h2>
                    <p className="text-xl text-white/80 max-w-3xl mx-auto">
                        Comprehensive vulnerability detection across all major attack vectors
                    </p>
                </motion.div>

                {/* Attack Surface Map */}
                <div className="relative">
                    <motion.div
                        initial={{ opacity: 0, scale: 0.9 }}
                        whileInView={{ opacity: 1, scale: 1 }}
                        viewport={{ once: true }}
                        transition={{ duration: 0.8 }}
                        className="relative h-[900px] rounded-3xl border border-white/10 bg-[#111827]/60 backdrop-blur-xl p-8"
                    >
                        {/* Central Codebase Icon */}
                        <motion.div
                            className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-20"
                            animate={{
                                scale: [1, 1.05, 1],
                            }}
                            transition={{
                                duration: 3,
                                repeat: Infinity,
                                ease: "easeInOut",
                            }}
                        >
                            <div className="relative">
                                <div className="absolute inset-0 bg-gradient-to-r from-[#2563EB] to-[#22D3EE] rounded-full blur-2xl opacity-50 animate-pulse" />
                                <div className="relative w-24 h-24 rounded-full bg-gradient-to-br from-[#2563EB] to-[#22D3EE] flex items-center justify-center ring-4 ring-[#0a1628] shadow-2xl">
                                    <Shield className="w-12 h-12 text-white" />
                                </div>
                            </div>
                        </motion.div>

                        {/* Vulnerability Category Nodes */}
                        {categories.map((category, index) => {
                            const Icon = category.icon;
                            const isHovered = hoveredCategory === category.id;

                            return (
                                <React.Fragment key={category.id}>
                                    {/* Connection Line */}
                                    <svg className="absolute inset-0 w-full h-full pointer-events-none">
                                        <motion.line
                                            x1="50%"
                                            y1="50%"
                                            x2={`${category.position.x}%`}
                                            y2={`${category.position.y}%`}
                                            stroke={category.color}
                                            strokeWidth="2"
                                            strokeDasharray="5,5"
                                            initial={{ pathLength: 0, opacity: 0 }}
                                            whileInView={{ pathLength: 1, opacity: isHovered ? 0.8 : 0.3 }}
                                            viewport={{ once: true }}
                                            transition={{ duration: 1, delay: index * 0.1 }}
                                        />
                                    </svg>

                                    {/* Category Node */}
                                    <motion.div
                                        initial={{ opacity: 0, scale: 0 }}
                                        whileInView={{ opacity: 1, scale: 1 }}
                                        viewport={{ once: true }}
                                        transition={{ duration: 0.5, delay: index * 0.15 }}
                                        className="absolute cursor-pointer"
                                        style={{
                                            left: `${category.position.x}%`,
                                            top: `${category.position.y}%`,
                                            transform: 'translate(-50%, -50%)',
                                        }}
                                        onMouseEnter={() => setHoveredCategory(category.id)}
                                        onMouseLeave={() => setHoveredCategory(null)}
                                    >
                                        {/* Glow effect */}
                                        <motion.div
                                            className="absolute inset-0 rounded-full blur-xl"
                                            style={{ backgroundColor: category.color }}
                                            animate={{
                                                opacity: isHovered ? 0.6 : 0.2,
                                                scale: isHovered ? 1.5 : 1,
                                            }}
                                            transition={{ duration: 0.3 }}
                                        />

                                        {/* Node */}
                                        <motion.div
                                            className={`relative w-16 h-16 rounded-full bg-gradient-to-br ${category.gradient} flex items-center justify-center ring-4 ring-[#0a1628] shadow-xl`}
                                            animate={{
                                                scale: isHovered ? 1.2 : 1,
                                            }}
                                            transition={{ duration: 0.3 }}
                                        >
                                            <Icon className="w-8 h-8 text-white" />
                                        </motion.div>

                                        {/* Tooltip on hover */}
                                        {isHovered && (
                                            <motion.div
                                                initial={{ opacity: 0, y: category.position.y > 50 ? -10 : 10 }}
                                                animate={{ opacity: 1, y: 0 }}
                                                className={`absolute ${category.position.y > 50 ? 'bottom-full mb-4' : 'top-full mt-4'} left-1/2 transform -translate-x-1/2 w-80 rounded-2xl border border-white/20 bg-[#111827]/95 backdrop-blur-xl p-6 shadow-2xl z-50`}
                                                style={{ zIndex: 100 }}
                                            >
                                                <div className="flex items-center gap-3 mb-4">
                                                    <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${category.gradient} flex items-center justify-center`}>
                                                        <Icon className="w-6 h-6 text-white" />
                                                    </div>
                                                    <h3 className="text-lg font-bold text-white">{category.title}</h3>
                                                </div>

                                                <div className="space-y-3">
                                                    {category.vulnerabilities.map((vuln, vIndex) => (
                                                        <motion.div
                                                            key={vIndex}
                                                            initial={{ opacity: 0, x: -10 }}
                                                            animate={{ opacity: 1, x: 0 }}
                                                            transition={{ delay: vIndex * 0.1 }}
                                                            className="p-3 rounded-lg bg-white/5 hover:bg-white/10 transition-colors cursor-pointer"
                                                            onClick={() => setSelectedVulnerability(vuln)}
                                                        >
                                                            <div className="flex items-start justify-between mb-2">
                                                                <span className="text-sm font-medium text-white">{vuln.name}</span>
                                                                <span
                                                                    className="px-2 py-0.5 rounded text-xs font-bold text-white"
                                                                    style={{ backgroundColor: getSeverityColor(vuln.severity) }}
                                                                >
                                                                    {vuln.severity}
                                                                </span>
                                                            </div>
                                                            <p className="text-xs text-white/60 font-mono mb-2">{vuln.example}</p>
                                                            {vuln.fixAvailable && (
                                                                <div className="flex items-center gap-1 text-xs text-[#22C55E]">
                                                                    <div className="w-1.5 h-1.5 rounded-full bg-[#22C55E]" />
                                                                    Fix available
                                                                </div>
                                                            )}
                                                        </motion.div>
                                                    ))}
                                                </div>
                                            </motion.div>
                                        )}
                                    </motion.div>
                                </React.Fragment>
                            );
                        })}
                    </motion.div>
                </div>
            </div>
        </section>
    );
}
