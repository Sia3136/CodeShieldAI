import { motion } from "motion/react";
import { Upload, FileCode, Settings, Brain, Shield, Bell, FileText, RefreshCcw } from "lucide-react";

export function Workflow() {
    const steps = [
        {
            icon: Upload,
            title: "Upload Code or Connect Repository",
            description: "Paste source code, upload files, or connect your GitHub repository using OAuth authentication to start the security scan.",
            color: "#2563EB",
        },
        {
            icon: FileCode,
            title: "Code Preprocessing & Parsing",
            description: "The system parses and structures your code, preparing it for advanced machine-learning analysis and vulnerability detection.",
            color: "#22D3EE",
        },
        {
            icon: Settings,
            title: "Model Selection",
            description: "GraphCodeBERT is used by default for optimal accuracy. Switch between multiple supported AI models based on your needs.",
            color: "#06B6D4",
        },
        {
            icon: Brain,
            title: "AI-Driven Vulnerability Analysis",
            description: "Advanced ML models analyze your code to detect SQL injection, XSS, command injection, and 12+ other security vulnerabilities.",
            color: "#8B5CF6",
        },
        {
            icon: Shield,
            title: "Risk Classification & Confidence Scoring",
            description: "Detected issues are classified by severity (Critical, High, Medium, Low) and assigned confidence scores for accuracy.",
            color: "#F97316",
        },
        {
            icon: Bell,
            title: "High-Risk Email Alerting",
            description: "Critical and high-severity vulnerabilities trigger instant email notifications with affected code lines and fix recommendations.",
            color: "#EF4444",
        },
        {
            icon: FileText,
            title: "Results & Detailed Reporting",
            description: "Access comprehensive vulnerability reports with severity levels, confidence scores, analytics dashboards, and remediation guidance.",
            color: "#22C55E",
        },
        {
            icon: RefreshCcw,
            title: "Remediation & Re-Scan",
            description: "Apply suggested fixes to your code and re-scan to validate improvements, update your security score, and track progress over time.",
            color: "#10B981",
        },
    ];

    return (
        <section className="relative py-32 px-6 overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-b from-slate-50 via-blue-50 to-purple-50 dark:from-slate-950 dark:via-blue-950 dark:to-slate-900" />

            {/* Vertical gradient line */}
            <div className="absolute left-1/2 top-32 bottom-32 w-px bg-gradient-to-b from-transparent via-blue-500 dark:via-blue-400 to-transparent opacity-20 hidden lg:block" />

            <div className="relative z-10 max-w-7xl mx-auto">
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.6 }}
                    className="text-center mb-20"
                >
                    <div className="inline-block px-4 py-2 rounded-full bg-blue-500/10 dark:bg-blue-500/10 border border-blue-500/20 dark:border-blue-400/20 text-blue-600 dark:text-cyan-400 text-sm mb-6">
                        How It Works
                    </div>
                    <h2 className="text-4xl lg:text-5xl font-bold text-slate-900 dark:text-white mb-6">
                        Advanced Machine Learning Pipeline
                        <br />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-cyan-500 to-purple-600 dark:from-blue-400 dark:via-cyan-400 dark:to-purple-400">
                            for Vulnerability Detection
                        </span>
                    </h2>
                    <p className="text-xl text-slate-600 dark:text-slate-400 max-w-3xl mx-auto">
                        Our AI-powered system analyzes your code through multiple stages to ensure comprehensive security coverage
                    </p>
                </motion.div>

                {/* Timeline */}
                <div className="relative max-w-5xl mx-auto">
                    {steps.map((step, index) => {
                        const Icon = step.icon;
                        const isEven = index % 2 === 0;

                        return (
                            <motion.div
                                key={index}
                                initial={{ opacity: 0, y: 40 }}
                                whileInView={{ opacity: 1, y: 0 }}
                                viewport={{ once: true, margin: "-100px" }}
                                transition={{ duration: 0.6, delay: index * 0.1 }}
                                className="relative mb-16 lg:mb-24 last:mb-0"
                            >
                                <div className={`grid lg:grid-cols-2 gap-8 items-center ${!isEven ? 'lg:grid-flow-dense' : ''}`}>
                                    {/* Content */}
                                    <div className={`${!isEven ? 'lg:col-start-2 lg:text-left' : 'lg:text-right'}`}>
                                        <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-full bg-slate-200/50 dark:bg-slate-800/40 border border-slate-300 dark:border-white/10 mb-4`}>
                                            <span className="text-cyan-600 dark:text-cyan-400 text-sm font-mono">Step {index + 1}</span>
                                        </div>
                                        <h3 className="text-2xl lg:text-3xl font-bold text-slate-900 dark:text-white mb-4">
                                            {step.title}
                                        </h3>
                                        <p className="text-lg text-slate-600 dark:text-slate-400 leading-relaxed max-w-md inline-block">
                                            {step.description}
                                        </p>
                                    </div>

                                    {/* Icon node - always in center on desktop */}
                                    <div className={`flex justify-center ${!isEven ? 'lg:col-start-1 lg:row-start-1' : ''}`}>
                                        <div className="relative">
                                            {/* Outer glow */}
                                            <div
                                                className="absolute inset-0 rounded-full blur-2xl opacity-40 dark:opacity-30"
                                                style={{
                                                    background: `radial-gradient(circle, ${step.color}, transparent 70%)`,
                                                }}
                                            />

                                            {/* Main circle */}
                                            <div
                                                className="relative w-28 h-28 rounded-full flex items-center justify-center backdrop-blur-sm"
                                                style={{
                                                    background: `linear-gradient(135deg, ${step.color}30, ${step.color}15)`,
                                                    border: `3px solid ${step.color}`,
                                                    boxShadow: `0 0 30px ${step.color}40, inset 0 0 20px ${step.color}20`,
                                                }}
                                            >
                                                <Icon className="h-12 w-12" style={{ color: step.color }} />

                                                {/* Pulsing ring */}
                                                <div
                                                    className="absolute inset-0 rounded-full animate-ping opacity-20"
                                                    style={{ border: `3px solid ${step.color}` }}
                                                />
                                            </div>

                                            {/* Step number badge */}
                                            <div
                                                className="absolute -top-2 -right-2 w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm shadow-lg"
                                                style={{
                                                    backgroundColor: step.color,
                                                    color: '#fff',
                                                    boxShadow: `0 0 20px ${step.color}80`,
                                                }}
                                            >
                                                {index + 1}
                                            </div>

                                            {/* Connecting line to next step (desktop only) */}
                                            {index < steps.length - 1 && (
                                                <div className="hidden lg:block absolute top-full left-1/2 -translate-x-1/2 w-0.5 h-24 bg-gradient-to-b from-current to-transparent opacity-30" style={{ color: step.color }} />
                                            )}
                                        </div>
                                    </div>

                                    {/* Empty space for alignment */}
                                    <div className={`hidden lg:block ${!isEven ? 'lg:col-start-2' : ''}`} />
                                </div>

                                {/* Mobile vertical connector */}
                                {index < steps.length - 1 && (
                                    <div className="lg:hidden flex justify-center mt-8">
                                        <div className="w-0.5 h-16 bg-gradient-to-b from-blue-500 dark:from-blue-400 to-transparent opacity-30" />
                                    </div>
                                )}
                            </motion.div>
                        );
                    })}
                </div>
            </div>
        </section>
    );
}
