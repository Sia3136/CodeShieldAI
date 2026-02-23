import React, { useState, useEffect } from "react";
import { VulnerabilityScanner } from "@/app/components/VulnerabilityScanner";
import { VulnerabilityDashboard } from "@/app/components/VulnerabilityDashboard";
import { CodeViewer } from "@/app/components/CodeViewer";
import { LandingPage } from "@/app/components/LandingPage";
import { RepositoryScanner } from "@/app/components/RepositoryScanner";
import { EnhancedAnalyticsDashboard } from "@/app/components/EnhancedAnalyticsDashboard";
import { HeroStatsBar } from "@/app/components/HeroStatsBar";
import { UserProfileButton } from "@/app/components/UserProfileButton";
import { UserAccountPage } from "@/app/components/UserAccountPage";
import { ScanHistory } from "@/app/components/ScanHistory";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/app/components/ui/tabs";
import {
  Shield,
  BarChart3,
  Code2,
  Brain,
  Github,
  Zap,
  Lock,
  Activity,
  Home,
  User,
  ArrowLeft,
  History,
} from "lucide-react";
import { Toaster } from "@/app/components/ui/sonner";
import { motion, AnimatePresence } from "motion/react";
import { ThemeProvider } from "@/app/components/ThemeProvider";
import { ThemeToggle } from "@/app/components/ThemeToggle";
import { Button } from "@/app/components/ui/button";
import Logo from './components/ui/Logo';
import { getToken, getCurrentUser } from '@/lib/auth-api';
import { DashboardView } from './DashboardView';

export default function App() {
  const [activeTab, setActiveTab] = useState("scanner");
  const [showLanding, setShowLanding] = useState(true);
  const [showAccount, setShowAccount] = useState(false);
  const [accountUser, setAccountUser] = useState<any>(null);
  const [loadingUser, setLoadingUser] = useState(false);

  // Check if user is already logged in on app load
  useEffect(() => {
    const checkAuth = async () => {
      const token = getToken();
      if (token) {
        setLoadingUser(true);
        try {
          // Attempt to fetch user profile to validate session
          const userData = await getCurrentUser(token);
          setAccountUser(userData);
          setShowLanding(false); // Skip landing if token is valid
        } catch (error) {
          console.error('Session validation failed:', error);
          // Token invalid/expired - keep landing page
        } finally {
          setLoadingUser(false);
        }
      }
    };
    checkAuth();
  }, []);

  // Fetch user data when account page is requested
  useEffect(() => {
    if (showAccount) {
      const fetchUser = async () => {
        setLoadingUser(true);
        const token = getToken();
        if (token) {
          try {
            const userData = await getCurrentUser(token);
            setAccountUser(userData);
          } catch (error) {
            console.error('Failed to fetch user:', error);
            setShowAccount(false);
          }
        } else {
          setShowAccount(false);
        }
        setLoadingUser(false);
      };
      fetchUser();
    }
  }, [showAccount]);


  if (showLanding) {
    console.log('Rendering landing page');
    return (
      <ThemeProvider>
        <AnimatePresence mode="wait">
          <motion.div
            key="landing"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            transition={{ duration: 0.5 }}
            className="min-h-screen bg-[#0a1628] text-slate-900 dark:text-white transition-colors duration-500"
          >
            <Toaster />



            <LandingPage
              onGetStarted={() => {
                console.log('onGetStarted called - setting showLanding to false');
                setShowLanding(false);
                console.log('showLanding should now be false');
              }}
              onNavigateToGitHub={() => {
                console.log('onNavigateToGitHub called');
                setShowLanding(false);
                setActiveTab('repository');
              }}
            />
          </motion.div>
        </AnimatePresence>
      </ThemeProvider>
    );
  }

  console.log('Past landing page check. showAccount:', showAccount, 'showLanding:', showLanding);

  // Show account page if requested
  if (showAccount) {
    console.log('Rendering account page');
    if (loadingUser) {
      return (
        <ThemeProvider>
          <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 dark:from-slate-950 dark:via-blue-950 dark:to-slate-900">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        </ThemeProvider>
      );
    }

    if (!accountUser) {
      setShowAccount(false);
      return null;
    }

    return (
      <ThemeProvider>
        <div className="min-h-screen bg-[#0a1628] text-white transition-colors duration-500">
          <Toaster />

          {/* Header */}
          <header className="relative border-b border-slate-200 dark:border-white/10 bg-white/80 dark:bg-black/30 backdrop-blur-xl">
            <div className="container mx-auto px-4 py-8">
              <div className="flex items-center justify-between">
                <motion.div
                  className="flex items-center gap-4"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.5 }}
                >
                  <div className="relative">
                    <div className="absolute inset-0 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-xl blur-lg opacity-75 animate-pulse" />
                    <div className="relative p-2 bg-white dark:bg-slate-900 rounded-xl shadow-2xl">
                      <Logo />
                    </div>
                  </div>
                  <div>
                    <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent">
                      My Account
                    </h1>
                    <p className="text-sm text-slate-700 dark:text-blue-200/80 flex items-center gap-2 mt-1">
                      <User className="w-4 h-4" />
                      Profile & Scan History
                    </p>
                  </div>
                </motion.div>

                <motion.div
                  className="flex items-center gap-4"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.5 }}
                >
                  <ThemeToggle />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowAccount(false)}
                    className="bg-slate-200/50 dark:bg-white/5 border-slate-300 dark:border-white/10 text-slate-900 dark:text-white hover:bg-slate-300/50 dark:hover:bg-white/10"
                  >
                    <ArrowLeft className="w-4 h-4 mr-2" />
                    <span className="hidden sm:inline">Back to Dashboard</span>
                  </Button>
                  <UserProfileButton
                    onLogout={() => {
                      setShowAccount(false);
                      setShowLanding(true);
                    }}
                    onViewAccount={() => setShowAccount(true)}
                  />
                </motion.div>
              </div>
            </div>
          </header>

          {/* Main Content */}
          <main className="relative container mx-auto px-4 py-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <UserAccountPage user={accountUser} />
            </motion.div>
          </main>
        </div>
      </ThemeProvider>
    );
  }

  console.log('Rendering dashboard, activeTab:', activeTab);

  return (
    <DashboardView
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      setShowLanding={setShowLanding}
      setShowAccount={setShowAccount}
    />
  );
}
