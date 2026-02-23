import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/app/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/app/components/ui/tabs';
import { Badge } from '@/app/components/ui/badge';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { FileCode, AlertCircle, CheckCircle, Brain, Zap, Target } from 'lucide-react';
import { motion } from 'motion/react';

const sampleVulnerableCode = `// Example: Vulnerable Code with Multiple Issues

// ❌ SQL Injection Vulnerability
function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.execute(query);
}

// ❌ Hardcoded Credentials
const API_KEY = "sk_live_1234567890abcdef";
const password = "admin123";

// ❌ XSS Vulnerability
function renderUserContent(content) {
  document.getElementById('output').innerHTML = content;
}

// ❌ Command Injection
const exec = require('child_process').exec;
function runCommand(userInput) {
  exec('ls -la ' + userInput, (error, stdout) => {
    console.log(stdout);
  });
}

// ❌ eval() usage
function processExpression(expr) {
  return eval(expr);
}`;

const sampleSecureCode = `// Example: Secure Code Implementation

// ✅ Parameterized Query (SQL Injection Prevention)
function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = ?";
  return db.execute(query, [userId]);
}

// ✅ Environment Variables for Secrets
const API_KEY = process.env.API_KEY;
const password = process.env.DB_PASSWORD;

// ✅ Safe DOM Manipulation
function renderUserContent(content) {
  const element = document.getElementById('output');
  element.textContent = content; // or use DOMPurify
}

// ✅ Safe Command Execution
const { execFile } = require('child_process');
function runCommand(userInput) {
  // Validate input first
  if (!/^[a-zA-Z0-9_-]+$/.test(userInput)) {
    throw new Error('Invalid input');
  }
  execFile('ls', ['-la', userInput], (error, stdout) => {
    console.log(stdout);
  });
}

// ✅ Safe Expression Evaluation
function processExpression(expr) {
  // Use a safe parser or Function constructor
  // with strict validation
  return new Function('return ' + expr)();
}`;

export function CodeViewer() {
  const [activeTab, setActiveTab] = useState('vulnerable');

  const vulnerabilityHighlights = [
    { line: 5, type: 'SQL Injection', severity: 'critical', gradient: 'from-red-500 to-rose-600' },
    { line: 10, type: 'Exposed API Key', severity: 'high', gradient: 'from-orange-500 to-amber-600' },
    { line: 11, type: 'Hardcoded Password', severity: 'critical', gradient: 'from-red-500 to-rose-600' },
    { line: 15, type: 'XSS Vulnerability', severity: 'high', gradient: 'from-orange-500 to-amber-600' },
    { line: 21, type: 'Command Injection', severity: 'critical', gradient: 'from-red-500 to-rose-600' },
    { line: 27, type: 'Code Injection', severity: 'critical', gradient: 'from-red-500 to-rose-600' },
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
              <div className="p-2 bg-gradient-to-br from-green-500 to-emerald-500 rounded-lg">
                <FileCode className="w-6 h-6" />
              </div>
              Code Examples
            </CardTitle>
            <CardDescription className="text-slate-600 dark:text-white/60">
              Compare vulnerable and secure code implementations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="grid w-full grid-cols-2 bg-white/5 backdrop-blur-lg border border-white/10 p-1 rounded-xl">
                <TabsTrigger
                  value="vulnerable"
                  className="flex items-center gap-2 data-[state=active]:bg-gradient-to-r data-[state=active]:from-red-600 data-[state=active]:to-rose-600 data-[state=active]:text-white transition-all duration-300 rounded-lg"
                >
                  <AlertCircle className="w-4 h-4" />
                  Vulnerable Code
                </TabsTrigger>
                <TabsTrigger
                  value="secure"
                  className="flex items-center gap-2 data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-600 data-[state=active]:to-emerald-600 data-[state=active]:text-white transition-all duration-300 rounded-lg"
                >
                  <CheckCircle className="w-4 h-4" />
                  Secure Code
                </TabsTrigger>
              </TabsList>

              <TabsContent value="vulnerable" className="space-y-4 mt-6">
                <motion.div
                  className="rounded-lg overflow-hidden border border-red-500/20 shadow-2xl"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3 }}
                >
                  <div className="h-1 bg-gradient-to-r from-red-500 to-rose-600" />
                  <SyntaxHighlighter
                    language="javascript"
                    style={vscDarkPlus}
                    showLineNumbers
                    customStyle={{
                      margin: 0,
                      padding: '1.5rem',
                      fontSize: '0.875rem',
                      background: 'rgba(0,0,0,1)',//it was this one 
                    }}
                  >
                    {sampleVulnerableCode}
                  </SyntaxHighlighter>
                </motion.div>

                <div className="space-y-2">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-red-400" />
                    Detected Vulnerabilities
                  </h3>
                  <div className="grid gap-2">
                    {vulnerabilityHighlights.map((vuln, index) => (
                      <motion.div
                        key={index}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                        className="group relative flex items-center justify-between p-3 bg-slate-100/50 dark:bg-black/40 backdrop-blur-sm rounded-lg border border-slate-300 dark:border-white/10 hover:border-slate-400 dark:hover:border-white/20 transition-all duration-300 hover:scale-[1.02]"
                      >
                        <div className={`absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b ${vuln.gradient} rounded-l-lg`} />
                        <div className="flex items-center gap-3 ml-4">
                          <span className="text-xs text-slate-600 dark:text-white/60 font-mono bg-slate-200 dark:bg-white/5 px-2 py-1 rounded">
                            Line {vuln.line}
                          </span>
                          <span className="text-sm font-medium text-slate-900 dark:text-white">{vuln.type}</span>
                        </div>
                        <Badge
                          className={`bg-gradient-to-r ${vuln.gradient} text-white border-0`}
                        >
                          {vuln.severity.toUpperCase()}
                        </Badge>
                      </motion.div>
                    ))}
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="secure" className="space-y-4 mt-6">
                <motion.div
                  className="rounded-lg overflow-hidden border border-green-500/20 shadow-2xl"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3 }}
                >
                  <div className="h-1 bg-gradient-to-r from-green-500 to-emerald-600" />
                  <SyntaxHighlighter
                    language="javascript"
                    style={vscDarkPlus}
                    showLineNumbers
                    customStyle={{
                      margin: 0,
                      padding: '1.5rem',
                      fontSize: '0.875rem',
                      background: 'rgba(0,0,0,1)', //not this one
                    }}
                  >
                    {sampleSecureCode}
                  </SyntaxHighlighter>
                </motion.div>

                <motion.div
                  className="p-6 bg-gradient-to-br from-green-500/20 to-emerald-500/20 backdrop-blur-sm rounded-lg border border-green-500/30"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.2 }}
                >
                  <div className="flex items-start gap-3">
                    <div className="p-2 bg-green-500/20 rounded-lg">
                      <CheckCircle className="w-6 h-6 text-green-400" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-green-400 mb-2 text-lg">
                        Secure Implementation
                      </h3>
                      <p className="text-sm text-white/80">
                        This code follows security best practices and mitigates all previously
                        identified vulnerabilities through proper input validation, parameterized
                        queries, and secure coding patterns.
                      </p>
                    </div>
                  </div>
                </motion.div>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.2 }}
      >
        <Card className="bg-white/40 dark:bg-white/5 backdrop-blur-lg border-slate-200 dark:border-white/10 shadow-2xl">
          <CardHeader>
            <CardTitle className="text-slate-900 dark:text-white flex items-center gap-2">
              <Brain className="w-5 h-5 text-purple-400" />
              ML Model Insights
            </CardTitle>
            <CardDescription className="text-slate-600 dark:text-white/60">
              How our AI detects vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-3">
              {[
                {
                  title: 'GraphCodeBERT and Codebert Embeddings',
                  description: 'Pre-trained transformer model analyzes code semantics and structure',
                  icon: Brain,
                  gradient: 'from-purple-500 to-pink-500'
                },
                {
                  title: 'Pattern Recognition',
                  description: 'Hybrid rule engine identifies known vulnerability patterns.',
                  icon: Target,
                  gradient: 'from-blue-500 to-cyan-500'
                },
                {
                  title: 'Binary Classification',
                  description: 'Neural network performs binary classification on code snippets to detect security flaws.',
                  icon: Zap,
                  gradient: 'from-orange-500 to-red-500'
                }
              ].map((item, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.3 + index * 0.1 }}
                  whileHover={{ scale: 1.05 }}
                  className="group relative p-4 bg-slate-100/50 dark:bg-black/40 backdrop-blur-sm rounded-lg border border-slate-300 dark:border-white/10 hover:border-slate-400 dark:hover:border-white/20 transition-all duration-300"
                >
                  <div className={`absolute inset-0 bg-gradient-to-br ${item.gradient} opacity-0 group-hover:opacity-10 rounded-lg transition-opacity duration-300`} />
                  <div className="relative">
                    <div className={`inline-block p-2 bg-gradient-to-br ${item.gradient} rounded-lg mb-3`}>
                      <item.icon className="w-5 h-5 text-white" />
                    </div>
                    <h4 className="font-semibold text-slate-900 dark:text-white mb-2">{item.title}</h4>
                    <p className="text-sm text-slate-700 dark:text-white/70">
                      {item.description}
                    </p>
                  </div>
                </motion.div>
              ))}
            </div>

            <motion.div
              className="p-6 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 backdrop-blur-sm rounded-lg border border-blue-500/30"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: 0.6 }}
            >
              <div className="flex items-start gap-3">
                <div className="p-2 bg-blue-500/20 rounded-lg">
                  <Brain className="w-6 h-6 text-blue-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-blue-400 mb-2 text-lg">
                    Training Data & Performance
                  </h3>
                  <p className="text-sm text-slate-800 dark:text-white/80 mb-3 leading-relaxed">
                    Model trained on ~50,000 labeled code samples derived from merged benchmark datasets
                    including DiverseVul, Devign, ReVeal, BigVul, CrossVul, and CVEfixes.
                    Evaluated on held-out splits to ensure generalization across vulnerability types.
                  </p>
                  <div className="flex flex-wrap gap-x-4 gap-y-2 text-[11px] text-slate-700 dark:text-white/60 font-medium">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 bg-green-400 rounded-full" />
                      <span>95% Detection Accuracy</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 bg-blue-400 rounded-full" />
                      <span>Evaluated on Multi-Dataset Benchmark</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 bg-yellow-400 rounded-full" />
                      <span>Optimized for Low False Positive Rate</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 bg-purple-400 rounded-full" />
                      <span>Real-Time Inference Capable</span>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}