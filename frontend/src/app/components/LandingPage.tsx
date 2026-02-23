import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, Brain, Zap, Target, Lock, Activity, CheckCircle, ArrowRight, Github, Code2, BarChart3, AlertTriangle, Upload, FileCode, Sparkles, Mail, FileText, RefreshCw, Plus, Minus } from 'lucide-react';
import { Button } from '@/app/components/ui/button';
import { Card, CardContent } from '@/app/components/ui/card';
import Logo from '../components/ui/Logo';
import { AuthModal } from '@/app/components/AuthModal';
import { AttackSurfaceMap } from '@/app/components/AttackSurfaceMap';
import { getToken } from '@/lib/auth-api';

interface LandingPageProps {
  onGetStarted: () => void;
  onNavigateToGitHub?: () => void;
}

export function LandingPage({ onGetStarted, onNavigateToGitHub }: LandingPageProps) {
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [openFaqIndex, setOpenFaqIndex] = useState<number | null>(null);

  const handleGetStarted = () => {
    const token = getToken();
    if (token) {
      // User is logged in, go to dashboard
      onGetStarted();
    } else {
      // User not logged in, show auth modal
      setShowAuthModal(true);
    }
  };

  const features = [
    {
      icon: Brain,
      title: 'Hybrid Transformer-Based Detection',
      description: 'Utilizes GraphCodeBERT embeddings combined with hybrid rule engine for structured vulnerability prediction.',
      gradient: 'from-[#2563EB] to-[#22D3EE]',
      color: '#2563EB',
    },
    {
      icon: Zap,
      title: 'Real-time Analysis',
      description: 'Instant scanning with results in seconds, not hours',
      gradient: 'from-[#22D3EE] to-[#06B6D4]',
      color: '#22D3EE',
    },
    {
      icon: Target,
      title: '95% Accuracy',
      description: 'Industry-leading accuracy with minimal false positives',
      gradient: 'from-[#22C55E] to-[#10B981]',
      color: '#22C55E',
    },
    {
      icon: Lock,
      title: 'Comprehensive Coverage',
      description: 'Detects SQL injection, XSS, command injection, and more',
      gradient: 'from-[#F97316] to-[#EF4444]',
      color: '#F97316',
    },
    {
      icon: BarChart3,
      title: 'Detailed Analytics',
      description: 'Interactive dashboards with trends and insights',
      gradient: 'from-[#8B5CF6] to-[#A855F7]',
      color: '#8B5CF6',
    },
    {
      icon: Activity,
      title: 'Actionable Insights',
      description: 'Get specific recommendations to fix vulnerabilities',
      gradient: 'from-[#EAB308] to-[#F59E0B]',
      color: '#EAB308',
    },
    {
      icon: Github,
      title: 'GitHub Integration',
      description: 'Scan entire repositories directly from GitHub with OAuth authentication',
      gradient: 'from-[#2563EB] to-[#1e40af]',
      color: '#2563EB',
    },
  ];

  const stats = [
    { value: '35', label: 'Scans Today', icon: Activity, color: '#2563EB' },
    { value: '49', label: 'Vulnerabilities Found', icon: AlertTriangle, color: '#EF4444' },
    { value: '10', label: 'Active Users (7d)', icon: Code2, color: '#22D3EE' },
    { value: '85%', label: 'Security Score', icon: Shield, color: '#22C55E' },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-[#0a1628]">
      {/* Hero Section */}
      <section className="relative flex-1 flex items-center justify-center px-6 py-20 overflow-hidden">
        {/* Background grid pattern */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1a1f35_1px,transparent_1px),linear-gradient(to_bottom,#1a1f35_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-0 dark:opacity-30 [mask-image:radial-gradient(ellipse_80%_50%_at_50%_0%,#000_70%,transparent_110%)]" />

        {/* Gradient orbs */}
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-[#2563EB] rounded-full mix-blend-screen filter blur-[128px] opacity-20 dark:opacity-20 animate-pulse" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-[#22D3EE] rounded-full mix-blend-screen filter blur-[128px] opacity-20 dark:opacity-20 animate-pulse" style={{ animationDelay: '1s' }} />

        <div className="relative z-10 max-w-7xl mx-auto w-full">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            {/* Left content */}
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.6 }}
              className="space-y-8"
            >
              <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#22D3EE]/10 border border-[#22D3EE]/20 backdrop-blur-sm">
                <div className="w-2 h-2 rounded-full bg-[#22D3EE] animate-pulse" />
                <span className="text-sm text-[#22D3EE] dark:text-[#22D3EE]">AI-Powered Security Analysis</span>
              </div>

              <div>
                <h1 className="text-5xl lg:text-7xl font-bold text-white leading-tight mb-4">
                  CodeShieldAI
                </h1>
                <h2 className="text-2xl lg:text-3xl text-transparent bg-clip-text bg-gradient-to-r from-[#2563EB] to-[#22D3EE] mb-6">
                  AI-Powered Vulnerability Detection & Alert System
                </h2>
              </div>

              <p className="text-xl text-white/90 leading-relaxed max-w-xl">
                Protect your code with intelligent security analysis. Instantly detect vulnerabilities using machine-learning–driven code understanding.
              </p>

              <div className="flex flex-wrap gap-4">
                <Button
                  size="lg"
                  onClick={handleGetStarted}
                  className="bg-gradient-to-r from-[#2563EB] to-[#22D3EE] hover:shadow-[0_0_30px_rgba(37,99,235,0.6)] transition-all duration-300 text-white border-0 px-8"
                >
                  <Shield className="mr-2 h-5 w-5" />
                  Start Scanning
                </Button>
              </div>

              {/* Quick stats */}
              <div className="grid grid-cols-2 gap-4 pt-8">
                {stats.map((stat, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, delay: 0.2 + index * 0.1 }}
                    className="rounded-xl border bg-white/40 dark:bg-[#111827]/60 backdrop-blur-xl p-4 border-slate-200 dark:border-white/10"
                    style={{ borderColor: `${stat.color}30` }}
                  >
                    <div className="text-3xl font-bold text-white mb-1" style={{ color: stat.color }}>{stat.value}</div>
                    <div className="text-sm text-white/80">{stat.label}</div>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            {/* Right dashboard mockup */}
            <motion.div
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8, delay: 0.2 }}
              className="relative"
            >
              {/* Main dashboard card */}
              <div className="relative rounded-[20px] border border-[#2563EB]/30 bg-white/60 dark:bg-[#111827]/60 backdrop-blur-xl p-6 shadow-[0_0_50px_rgba(37,99,235,0.3)]">
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <Shield className="h-6 w-6 text-[#22D3EE]" />
                    <h3 className="text-white">Security Scan Results</h3>
                  </div>
                  <div className="px-3 py-1 rounded-lg bg-[#22C55E]/20 border border-[#22C55E]/30 text-[#22C55E] text-sm">
                    Complete
                  </div>
                </div>

                {/* Vulnerability counts */}
                <div className="grid grid-cols-3 gap-4 mb-6">
                  <div className="rounded-xl bg-[#EF4444]/10 border border-[#EF4444]/30 p-4">
                    <div className="text-3xl font-bold text-[#EF4444] mb-1">3</div>
                    <div className="text-xs text-white/70">Critical</div>
                  </div>
                  <div className="rounded-xl bg-[#F97316]/10 border border-[#F97316]/30 p-4">
                    <div className="text-3xl font-bold text-[#F97316] mb-1">12</div>
                    <div className="text-xs text-white/70">High</div>
                  </div>
                  <div className="rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/30 p-4">
                    <div className="text-3xl font-bold text-[#22D3EE] mb-1">28</div>
                    <div className="text-xs text-white/70">Medium</div>
                  </div>
                </div>

                {/* Code snippet with issue */}
                <div className="rounded-xl bg-black/40 border border-[#2563EB]/20 p-4 mb-6 font-mono text-sm">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-4 w-4 text-[#EF4444] mt-1 flex-shrink-0" />
                    <div className="flex-1">
                      <div className="text-slate-500 dark:text-slate-500 text-xs mb-2">auth.js:42</div>
                      <div className="text-slate-700 dark:text-slate-300">
                        <span className="text-[#EF4444] bg-[#EF4444]/10 px-1">password</span>
                        <span className="text-slate-600 dark:text-slate-400"> stored in plain text</span>
                      </div>
                      <div className="text-[#22D3EE] text-xs mt-2">
                        → Use bcrypt for password hashing
                      </div>
                    </div>
                  </div>
                </div>

                {/* Security score */}
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm text-white/70 mb-1">Security Score</div>
                    <div className="flex items-center gap-2">
                      <div className="text-2xl font-bold text-[#F97316]">C</div>
                      <div className="text-sm text-white/70">(62/100)</div>
                    </div>
                  </div>
                  <div className="relative w-20 h-20">
                    <svg className="transform -rotate-90 w-20 h-20">
                      <circle
                        cx="40"
                        cy="40"
                        r="32"
                        stroke="#1a1f35"
                        strokeWidth="6"
                        fill="transparent"
                      />
                      <circle
                        cx="40"
                        cy="40"
                        r="32"
                        stroke="#F97316"
                        strokeWidth="6"
                        fill="transparent"
                        strokeDasharray={2 * Math.PI * 32}
                        strokeDashoffset={2 * Math.PI * 32 * (1 - 0.62)}
                        className="transition-all duration-1000"
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center text-slate-900 dark:text-white font-bold">
                      62
                    </div>
                  </div>
                </div>
              </div>

              {/* Floating notification card */}
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.6, delay: 0.8 }}
                className="absolute -right-4 -bottom-4 rounded-2xl border border-[#22C55E]/30 bg-white/80 dark:bg-[#111827]/80 backdrop-blur-xl p-4 shadow-[0_0_30px_rgba(34,197,94,0.2)] max-w-[200px]"
              >
                <div className="flex items-start gap-3">
                  <CheckCircle className="h-5 w-5 text-[#22C55E] flex-shrink-0" />
                  <div>
                    <div className="text-sm text-white mb-1">Fix Applied</div>
                    <div className="text-xs text-white/70">
                      SQL injection vulnerability resolved
                    </div>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="relative px-6 py-32 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-slate-100/50 to-transparent dark:via-[#111827] dark:to-transparent" />

        {/* Grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1a1f35_1px,transparent_1px),linear-gradient(to_bottom,#1a1f35_1px,transparent_1px)] bg-[size:3rem_3rem] opacity-0 dark:opacity-20" />

        {/* Accent glows */}
        <div className="absolute top-1/4 left-0 w-96 h-96 bg-[#2563EB] rounded-full mix-blend-screen filter blur-[200px] opacity-0 dark:opacity-10" />
        <div className="absolute bottom-1/4 right-0 w-96 h-96 bg-[#22D3EE] rounded-full mix-blend-screen filter blur-[200px] opacity-0 dark:opacity-10" />

        <div className="relative z-10 max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-20"
          >
            <div className="inline-block px-4 py-2 rounded-full bg-[#2563EB]/10 border border-[#2563EB]/20 text-[#22D3EE] text-sm mb-6">
              Powerful Features
            </div>
            <h2 className="text-4xl lg:text-5xl font-bold text-white mb-6">
              Built with <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#2563EB] to-[#22D3EE]">Cutting-Edge ML</span>
              <br />
              Technology
            </h2>
            <p className="text-xl text-white/80 max-w-3xl mx-auto">
              Keep your code secure with advanced machine learning models and real-time analysis
            </p>
          </motion.div>

          {/* Features grid */}
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, margin: "-50px" }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                  onClick={() => {
                    if (feature.title === 'GitHub Integration' && onNavigateToGitHub) {
                      onNavigateToGitHub();
                    }
                  }}
                  className={`group relative rounded-2xl border border-white/10 dark:border-white/10 bg-white/50 dark:bg-[#111827]/60 backdrop-blur-xl p-8 hover:border-[#2563EB]/40 hover:scale-105 transition-all duration-300 hover:shadow-[0_0_40px_rgba(37,99,235,0.2)] ${feature.title === 'GitHub Integration' && onNavigateToGitHub ? 'cursor-pointer' : ''}`}
                >
                  {/* Hover glow effect */}
                  <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-[#2563EB]/0 to-[#22D3EE]/0 group-hover:from-[#2563EB]/10 group-hover:to-[#22D3EE]/10 transition-all duration-300" />

                  <div className="relative">
                    {/* Icon */}
                    <div className="mb-6">
                      <div
                        className={`w-14 h-14 rounded-2xl bg-gradient-to-br ${feature.gradient} p-0.5`}
                      >
                        <div className="w-full h-full rounded-2xl bg-white dark:bg-[#111827] flex items-center justify-center">
                          <Icon className="h-7 w-7" style={{ color: feature.color }} />
                        </div>
                      </div>
                    </div>

                    {/* Content */}
                    <h3 className="text-xl text-white mb-3 group-hover:text-[#22D3EE] transition-colors">
                      {feature.title}
                    </h3>
                    <p className="text-white/70 leading-relaxed">
                      {feature.description}
                    </p>

                    {/* Decorative corner accent */}
                    <div className="absolute top-0 right-0 w-20 h-20 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                      <div className={`absolute top-0 right-0 w-full h-full bg-gradient-to-br ${feature.gradient} rounded-full blur-2xl opacity-20`} />
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* How It Works - Workflow Section */}
      <section className="relative px-6 py-32 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#0f1a2e] to-transparent" />

        {/* Grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1a1f35_1px,transparent_1px),linear-gradient(to_bottom,#1a1f35_1px,transparent_1px)] bg-[size:3rem_3rem] opacity-20" />

        <div className="relative z-10 max-w-7xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-20"
          >
            <div className="inline-block px-4 py-2 rounded-full bg-[#2563EB]/10 border border-[#2563EB]/20 text-[#22D3EE] text-sm mb-6">
              ML Pipeline
            </div>
            <h2 className="text-4xl lg:text-5xl font-bold text-white mb-6">
              How It <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#2563EB] to-[#22D3EE]">Works</span>
            </h2>
            <p className="text-xl text-white/80 max-w-3xl mx-auto">
              Advanced machine learning pipeline for intelligent vulnerability detection
            </p>
          </motion.div>

          {/* Workflow Steps */}
          <div className="relative space-y-12">
            {/* Center line for desktop */}
            <div className="hidden md:block absolute left-1/2 top-0 bottom-0 w-0.5 bg-gradient-to-b from-[#2563EB] via-[#8B5CF6] to-[#22D3EE] transform -translate-x-1/2" />

            {[
              {
                step: 'Step 1',
                title: 'Upload Code or Connect Repository',
                description: 'Paste source code, upload files, or connect your GitHub repository via OAuth to start the scan.',
                icon: Upload,
                gradient: 'from-[#2563EB] to-[#22D3EE]',
                color: '#2563EB',
              },
              {
                step: 'Step 2',
                title: 'Code Preprocessing & Parsing',
                description: 'The system parses and structures the code to prepare it for machine-learning analysis.',
                icon: FileCode,
                gradient: 'from-[#8B5CF6] to-[#A855F7]',
                color: '#8B5CF6',
              },
              {
                step: 'Step 3',
                title: 'Model Selection',
                description: 'GraphCodeBERT is used by default, with the option to switch to other supported models.',
                icon: Brain,
                gradient: 'from-[#A855F7] to-[#EC4899]',
                color: '#A855F7',
              },
              {
                step: 'Step 4',
                title: 'AI-Driven Vulnerability Analysis',
                description: 'The selected model analyzes the code to detect potential security vulnerabilities.',
                icon: Sparkles,
                gradient: 'from-[#F97316] to-[#EAB308]',
                color: '#F97316',
              },
              {
                step: 'Step 5',
                title: 'Risk Classification & Confidence Scoring',
                description: 'Detected issues are classified by severity and assigned confidence scores.',
                icon: BarChart3,
                gradient: 'from-[#EAB308] to-[#22C55E]',
                color: '#EAB308',
              },
              {
                step: 'Step 6',
                title: 'High-Risk Alerting (Email Notifications)',
                description: 'High-severity vulnerabilities trigger email alerts with affected code lines and fix recommendations.',
                icon: Mail,
                gradient: 'from-[#EF4444] to-[#F97316]',
                color: '#EF4444',
              },
              {
                step: 'Step 7',
                title: 'Results & Detailed Reporting',
                description: 'Users receive a comprehensive vulnerability report with severity levels, confidence scores, and remediation guidance.',
                icon: FileText,
                gradient: 'from-[#22C55E] to-[#10B981]',
                color: '#22C55E',
              },
              {
                step: 'Step 8',
                title: 'Remediation & Re-Scan',
                description: 'Apply fixes and re-scan the code to validate improvements and update the security score.',
                icon: RefreshCw,
                gradient: 'from-[#22D3EE] to-[#06B6D4]',
                color: '#22D3EE',
              },
            ].map((item, index) => {
              const isLeft = index % 2 === 0;
              const Icon = item.icon;
              return (
                <motion.div
                  key={item.step}
                  className={`relative flex items-center ${isLeft ? 'md:justify-start' : 'md:justify-end'}`}
                  initial={{ opacity: 0, x: isLeft ? -50 : 50, y: 20 }}
                  whileInView={{ opacity: 1, x: 0, y: 0 }}
                  viewport={{ once: true, margin: "-50px", amount: 0.3 }}
                  transition={{ duration: 0.5, delay: index * 0.08, ease: "easeOut" }}
                >
                  {/* Center dot for desktop */}
                  <div className="hidden md:block absolute left-1/2 transform -translate-x-1/2">
                    <div className={`w-12 h-12 rounded-full bg-gradient-to-br ${item.gradient} shadow-lg flex items-center justify-center ring-4 ring-[#0a1628]`}>
                      <div className="w-6 h-6 rounded-full bg-white" />
                    </div>
                  </div>

                  {/* Content Card */}
                  <div className={`w-full md:w-5/12 ${isLeft ? 'md:pr-12' : 'md:pl-12'}`}>
                    <div className={`relative rounded-2xl border border-white/10 bg-[#111827]/60 backdrop-blur-xl p-6 hover:border-[${item.color}]/40 transition-all duration-300 hover:shadow-[0_0_40px_rgba(37,99,235,0.15)]`}>
                      {/* Hover glow effect */}
                      <div className={`absolute inset-0 rounded-2xl bg-gradient-to-br ${item.gradient} opacity-0 hover:opacity-5 transition-opacity duration-300`} />

                      <div className="relative flex items-start gap-4">
                        {/* Icon */}
                        <div className={`flex-shrink-0 w-14 h-14 rounded-xl bg-gradient-to-br ${item.gradient} shadow-lg flex items-center justify-center`}>
                          <Icon className="w-7 h-7 text-white" />
                        </div>

                        {/* Text Content */}
                        <div className="flex-1">
                          <div className={`inline-block px-3 py-1 rounded-full bg-gradient-to-r ${item.gradient} text-white text-xs font-bold mb-2`}>
                            {item.step}
                          </div>
                          <h3 className="text-xl font-bold text-white mb-2">
                            {item.title}
                          </h3>
                          <p className="text-white/70 text-sm leading-relaxed">
                            {item.description}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Attack Surface Map */}
      <AttackSurfaceMap />

      {/* Padding after Attack Surface Map */}
      <div className="h-32" />

      {/* FAQ Section */}
      <section className="relative px-6 py-24 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#111827]/50 to-transparent" />
        <div className="relative z-10 max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl lg:text-5xl font-bold text-white mb-6">
              Common <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#2563EB] to-[#22D3EE]">Questions</span>
            </h2>
            <p className="text-xl text-white/80 max-w-2xl mx-auto">
              Everything you need to know about CodeShieldAI and how it protects your application.
            </p>
          </motion.div>

          <div className="space-y-4">
            {[
              {
                q: "What is a vulnerability, and why is it important to detect it?",
                a: "A vulnerability is a weakness in source code that can be exploited to compromise an application’s security. Detecting vulnerabilities early helps prevent data breaches, unauthorized access, and costly security incidents before the software is deployed."
              },
              {
                q: "What is a Code Vulnerability Scanner?",
                a: "A Code Vulnerability Scanner is a tool that analyzes source code to identify security weaknesses and insecure coding patterns. This scanner uses machine learning to detect vulnerabilities by analyzing code structure and logic rather than executing the application."
              },
              {
                q: "How can I scan my code using this tool?",
                a: "You can scan code by connecting your GitHub repository or by providing a public repository URL. The scanner fetches the source code and performs static analysis without modifying or executing the code."
              },
              {
                q: "What types of vulnerabilities can the scanner detect?",
                a: "The scanner detects a wide range of code-level security vulnerabilities, including injection attacks, web-exploit patterns in code (such as XSS and CSRF), access control flaws, insecure configurations, unsafe deserialization, and vulnerable third-party dependencies. These detections are mapped to CWE-based secure coding standards."
              },
              {
                q: "Is it safe to scan my GitHub repository?",
                a: "Yes. The scanner performs read-only analysis of the code. It does not push changes, execute files, or expose private data. Public repositories can be scanned without authentication."
              },
              {
                q: "What do I get after the scan is complete?",
                a: "After the scan, you receive a detailed report containing detected vulnerabilities, severity levels, affected files or code snippets, and clear remediation guidance, including fix suggestions where available."
              }
            ].map((faq, index) => {
              const isOpen = openFaqIndex === index;
              return (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: index * 0.1 }}
                  className="rounded-2xl border border-white/10 bg-[#111827]/60 backdrop-blur-xl overflow-hidden"
                >
                  <button
                    onClick={() => setOpenFaqIndex(isOpen ? null : index)}
                    className="w-full px-8 py-6 flex items-center justify-between text-left hover:bg-white/5 transition-colors group"
                  >
                    <span className="text-xl font-semibold text-white group-hover:text-[#22D3EE] transition-colors pr-8 antialiased">
                      {faq.q}
                    </span>
                    <div className={`p-2 rounded-lg bg-white/5 group-hover:bg-[#2563EB]/20 transition-all duration-300 ${isOpen ? 'text-[#EF4444]' : 'text-white'}`}>
                      {isOpen ? <Minus className="h-5 w-5" /> : <Plus className="h-5 w-5" />}
                    </div>
                  </button>
                  <AnimatePresence>
                    {isOpen && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3, ease: 'easeInOut' }}
                      >
                        <div className="px-8 pb-6 text-white/70 text-lg leading-relaxed border-t border-white/5 pt-4 bg-white/5">
                          {faq.a}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="relative px-6 py-32 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-slate-100 to-transparent dark:from-transparent dark:via-[#111827] dark:to-transparent" />

        {/* Animated grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#2563EB_1px,transparent_1px),linear-gradient(to_bottom,#2563EB_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-0 dark:opacity-10" />

        {/* Glowing orbs */}
        <div className="absolute top-1/2 left-1/4 w-96 h-96 bg-[#2563EB] rounded-full mix-blend-screen filter blur-[150px] opacity-0 dark:opacity-30 animate-pulse" />
        <div className="absolute top-1/2 right-1/4 w-96 h-96 bg-[#22D3EE] rounded-full mix-blend-screen filter blur-[150px] opacity-0 dark:opacity-30 animate-pulse" style={{ animationDelay: '1s' }} />

        <div className="relative z-10 max-w-4xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
          >
            {/* Icon badge */}
            <div className="inline-flex items-center justify-center mb-8">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-[#2563EB] to-[#22D3EE] rounded-full blur-xl opacity-60" />
                <div className="relative w-20 h-20 rounded-full bg-gradient-to-br from-[#2563EB] to-[#22D3EE] flex items-center justify-center">
                  <Shield className="h-10 w-10 text-white" />
                </div>
                <div className="absolute -top-1 -right-1">
                  <Sparkles className="h-6 w-6 text-[#22D3EE] animate-pulse" />
                </div>
              </div>
            </div>

            {/* Heading */}
            <h2 className="text-4xl lg:text-6xl font-bold text-white mb-6">
              Ready to Secure Your Code?
            </h2>

            <p className="text-xl lg:text-2xl text-white/80 mb-12 max-w-3xl mx-auto leading-relaxed">
              Start detecting vulnerabilities with{" "}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#2563EB] to-[#22D3EE]">
                AI-powered analysis
              </span>{" "}
              in seconds
            </p>

            {/* CTA Button */}
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <Button
                size="lg"
                onClick={handleGetStarted}
                className="bg-gradient-to-r from-[#2563EB] to-[#22D3EE] hover:shadow-[0_0_50px_rgba(37,99,235,0.6)] transition-all duration-300 text-white border-0 px-12 py-6 text-lg group"
              >
                Start Scanning Now
                <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
              </Button>
            </motion.div>

            {/* Scan Statistics */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: 0.4 }}
              className="grid grid-cols-3 gap-6 mt-12 max-w-3xl mx-auto"
            >
              <div className="p-6 rounded-xl border border-white/10 bg-white/5 backdrop-blur-sm text-center">
                <div className="text-4xl font-bold text-white mb-2">500+</div>
                <div className="text-sm text-white/70">Scans Completed</div>
              </div>
              <div className="p-6 rounded-xl border border-white/10 bg-white/5 backdrop-blur-sm text-center">
                <div className="text-4xl font-bold text-white mb-2">99.8%</div>
                <div className="text-sm text-white/70">Detection Rate</div>
              </div>
              <div className="p-6 rounded-xl border border-white/10 bg-white/5 backdrop-blur-sm text-center">
                <div className="text-4xl font-bold text-white mb-2">&lt; 30s</div>
                <div className="text-sm text-white/70">Average Scan Time</div>
              </div>
            </motion.div>


          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative px-6 py-8 border-t border-white/10">
        <div className="max-w-7xl mx-auto text-center">
          <p className="text-white/60 text-sm">
            © 2026 CodeShieldAI. All rights reserved.
          </p>
        </div>
      </footer>

      {/* Auth Modal */}
      <AuthModal
        isOpen={showAuthModal}
        onClose={() => setShowAuthModal(false)}
        onSuccess={() => {
          // Navigate to dashboard after successful auth
          onGetStarted();
        }}
      />
    </div>
  );
}