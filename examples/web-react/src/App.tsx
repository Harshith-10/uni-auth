import { useEffect, useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "./components/ui/alert";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";
import { authClient, getClientToken, useSession } from "./lib/auth-client";
import { Navbar } from "./components/Navbar";
import { AuthCard } from "./components/AuthCard";
import { AuthDialog } from "./components/AuthDialog";
import { ImpersonationBanner } from "./components/ImpersonationBanner";
import { MetricCards } from "./components/MetricCards";
import { SaasVerificationCard } from "./components/SaasVerificationCard";
import { ActiveSessionsCard } from "./components/ActiveSessionsCard";
import { AdminConsoleCard } from "./components/AdminConsoleCard";
import { ApiDiagnosticsCard } from "./components/ApiDiagnosticsCard";
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  KeyRound,
  Laptop,
  RefreshCw,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";

export function App() {
  const { data: session, isPending, refetch: refetchSession } = useSession();

  // Navigation & tabs
  const [authTab, setAuthTab] = useState<string>("signin");
  const [dashboardTab, setDashboardTab] = useState<string>("overview");
  const [authModalOpen, setAuthModalOpen] = useState(false);

  // Theme mode (persisted to localStorage)
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("theme");
      if (saved === "light" || saved === "dark") return saved;
      return document.documentElement.classList.contains("dark") ? "dark" : "light";
    }
    return "dark";
  });

  // Auth form inputs
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [isAuthLoading, setIsAuthLoading] = useState(false);
  const [message, setMessage] = useState<{
    type: "default" | "destructive";
    text: string;
  } | null>(null);

  // Protected SaaS endpoint state
  const [saasData, setSaasData] = useState<any>(null);
  const [isLoadingSaas, setIsLoadingSaas] = useState(false);
  const [saasError, setSaasError] = useState<string | null>(null);

  // Active Sessions state
  const [sessions, setSessions] = useState<any[]>([]);
  const [isLoadingSessions, setIsLoadingSessions] = useState(false);

  // Admin users state
  const [adminUsers, setAdminUsers] = useState<any[]>([]);
  const [adminTotal, setAdminTotal] = useState<number>(0);
  const [adminSearch, setAdminSearch] = useState("");
  const [isLoadingAdmin, setIsLoadingAdmin] = useState(false);

  // Computed role & impersonation
  const userRole = (session?.user as any)?.role || "user";
  const isAdmin = String(userRole)
    .split(",")
    .some((r) => r.trim() === "admin");
  const impersonatedBy = (session?.session as any)?.impersonatedBy as
    | string
    | null
    | undefined;

  // Sync theme to document element
  useEffect(() => {
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
    localStorage.setItem("theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  };

  // Load session-dependent data
  useEffect(() => {
    if (session?.user) {
      loadSessions();
      loadSaasData();
      if (isAdmin) {
        loadAdminUsers();
      }
    }
  }, [session?.user?.id, userRole, impersonatedBy]);

  // Load active sessions
  const loadSessions = async () => {
    setIsLoadingSessions(true);
    try {
      const res = await authClient.listSessions();
      if (res.data) {
        setSessions(res.data);
      }
    } catch (e: any) {
      console.error("Failed to load sessions:", e);
    } finally {
      setIsLoadingSessions(false);
    }
  };

  // Load protected /api/saas/me
  const loadSaasData = async () => {
    setIsLoadingSaas(true);
    setSaasError(null);
    try {
      const host =
        window.location.hostname === "127.0.0.1" ? "127.0.0.1" : "localhost";
      const saasUrl = `http://${host}:3000/api/saas/me`;
      const headers: Record<string, string> = {};
      const token = getClientToken();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const res = await fetch(saasUrl, {
        credentials: "include",
        headers,
      });

      if (res.ok) {
        const data = await res.json();
        setSaasData(data);
      } else {
        const text = await res.text();
        setSaasError(`HTTP ${res.status}: ${text || res.statusText}`);
      }
    } catch (e: any) {
      setSaasError(e?.message || "Failed to reach SaaS endpoint");
    } finally {
      setIsLoadingSaas(false);
    }
  };

  // Load admin user directory
  const loadAdminUsers = async (searchOverride?: string) => {
    setIsLoadingAdmin(true);
    try {
      const queryValue =
        searchOverride !== undefined ? searchOverride : adminSearch;
      const res = await authClient.admin.listUsers({
        query: {
          searchValue: queryValue.trim() || undefined,
          searchField: "email",
          searchOperator: "contains",
          limit: 50,
          offset: 0,
          sortBy: "createdAt",
          sortDirection: "desc",
        },
      });
      if (res.data) {
        setAdminUsers(res.data.users || []);
        setAdminTotal(res.data.total ?? res.data.users?.length ?? 0);
      }
    } catch (e: any) {
      console.error("Failed to list users:", e);
    } finally {
      setIsLoadingAdmin(false);
    }
  };

  // 1-Click Fill Demo Account
  const fillDemoAccount = (demoEmail: string, demoPassword: string) => {
    setAuthTab("signin");
    setEmail(demoEmail);
    setPassword(demoPassword);
    setMessage({
      type: "default",
      text: `Populated credentials for ${demoEmail}. Click "Sign In" to authenticate.`,
    });
  };

  // Sign up
  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAuthLoading(true);
    setMessage({ type: "default", text: "Registering account..." });
    try {
      const res = await authClient.signUp.email({
        name,
        email,
        password,
      });
      if (res.error) {
        setMessage({
          type: "destructive",
          text: res.error.message || "Registration failed",
        });
      } else {
        setMessage(null);
        setAuthModalOpen(false);
        await refetchSession();
      }
    } finally {
      setIsAuthLoading(false);
    }
  };

  // Sign in
  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsAuthLoading(true);
    setMessage({ type: "default", text: "Authenticating..." });
    try {
      const res = await authClient.signIn.email({
        email,
        password,
      });
      if (res.error) {
        setMessage({
          type: "destructive",
          text: res.error.message || "Sign in failed. Check credentials or user status.",
        });
      } else {
        setMessage(null);
        setAuthModalOpen(false);
        await refetchSession();
      }
    } finally {
      setIsAuthLoading(false);
    }
  };

  // Social sign in
  const handleSocialSignIn = async (provider: "google" | "github") => {
    setMessage({ type: "default", text: `Redirecting to ${provider}...` });
    try {
      await authClient.signIn.social({
        provider,
        callbackURL: window.location.origin,
      });
    } catch (err: any) {
      setMessage({
        type: "destructive",
        text: err?.message || "Social sign-in failed",
      });
    }
  };

  // Sign out
  const handleSignOut = async () => {
    await authClient.signOut();
    setSaasData(null);
    setSessions([]);
    setAdminUsers([]);
    setDashboardTab("overview");
    setMessage({ type: "default", text: "Signed out successfully." });
  };

  // Revoke session
  const handleRevokeSession = async (token: string) => {
    try {
      await authClient.revokeSession({ token });
      setMessage({ type: "default", text: "Session revoked successfully." });
      await loadSessions();
    } catch (e: any) {
      setMessage({
        type: "destructive",
        text: e?.message || "Failed to revoke session",
      });
    }
  };

  // Create user from Admin console
  const handleCreateUser = async (user: {
    name: string;
    email: string;
    password: string;
    role: "user" | "admin";
  }) => {
    const res = await authClient.admin.createUser({
      name: user.name,
      email: user.email,
      password: user.password,
      role: user.role,
    });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to create user",
      });
    } else {
      setMessage({
        type: "default",
        text: `Provisioned user ${res.data?.user?.email} with role "${user.role}"`,
      });
      await loadAdminUsers();
    }
  };

  // Promote / Demote user role
  const handleToggleRole = async (userId: string, currentRole?: string) => {
    const nextRole = currentRole === "admin" ? "user" : "admin";
    const res = await authClient.admin.setRole({
      userId,
      role: nextRole,
    });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to update role",
      });
    } else {
      setMessage({
        type: "default",
        text: `Updated user role to "${nextRole}"`,
      });
      await loadAdminUsers();
    }
  };

  // Ban / Unban user
  const handleToggleBan = async (userId: string, currentlyBanned?: boolean) => {
    const res = currentlyBanned
      ? await authClient.admin.unbanUser({ userId })
      : await authClient.admin.banUser({
          userId,
          banReason: "Suspended by administrator",
        });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to update account status",
      });
    } else {
      setMessage({
        type: "default",
        text: currentlyBanned ? "User account unbanned" : "User account suspended",
      });
      await loadAdminUsers();
    }
  };

  // Impersonate user
  const handleImpersonate = async (userId: string) => {
    const res = await authClient.admin.impersonateUser({ userId });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to impersonate user",
      });
    } else {
      setDashboardTab("overview");
      setMessage({
        type: "default",
        text: "Impersonation session established",
      });
      await refetchSession();
      await loadSaasData();
      await loadSessions();
    }
  };

  // Stop impersonating
  const handleStopImpersonating = async () => {
    const res = await authClient.admin.stopImpersonating();
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to exit impersonation",
      });
    } else {
      setMessage({
        type: "default",
        text: "Returned to original administrator session",
      });
      await refetchSession();
      await loadSaasData();
      await loadSessions();
    }
  };

  // Delete user
  const handleDeleteUser = async (userId: string) => {
    const res = await authClient.admin.removeUser({ userId });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to remove user",
      });
    } else {
      setMessage({
        type: "default",
        text: "User account deleted successfully",
      });
      await loadAdminUsers();
    }
  };

  // Loading state
  if (isPending) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-background text-foreground">
        <div className="flex flex-col items-center gap-3 text-center">
          <div className="size-10 bg-primary/10 text-primary flex items-center justify-center shadow-xs">
            <RefreshCw className="size-5 animate-spin" />
          </div>
          <div className="space-y-1">
            <h2 className="text-sm font-semibold">Connecting to Uni-Auth</h2>
            <p className="text-xs text-muted-foreground">
              Verifying Better-Auth session with Axum backend...
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground antialiased selection:bg-primary/20 selection:text-primary">
      {/* 1. REWORKED SHADCN HEADER */}
      <Navbar
        session={session}
        isAdmin={isAdmin}
        userRole={userRole}
        impersonatedBy={impersonatedBy}
        theme={theme}
        onToggleTheme={toggleTheme}
        onSignOut={handleSignOut}
        onStopImpersonating={handleStopImpersonating}
        onOpenAuthModal={() => setAuthModalOpen(true)}
        onSelectTab={(tab) => {
          setDashboardTab(tab);
          if (tab === "admin") loadAdminUsers();
        }}
      />

      {/* 2. MAIN APPLICATION CONTAINER */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Global notification alert if present */}
        {message && (
          <Alert variant={message.type} className="animate-in fade-in duration-200">
            {message.type === "destructive" ? (
              <AlertCircle className="size-4" />
            ) : (
              <CheckCircle2 className="size-4" />
            )}
            <AlertTitle className="text-xs font-semibold">
              {message.type === "destructive" ? "Notice" : "Status"}
            </AlertTitle>
            <AlertDescription className="text-xs flex items-center justify-between">
              <span>{message.text}</span>
              <Button
                variant="ghost"
                size="xs"
                onClick={() => setMessage(null)}
                className="h-5 px-1.5 text-[10px] text-muted-foreground hover:text-foreground"
              >
                Dismiss
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {/* 3. AUTHENTICATED VS UNAUTHENTICATED VIEWS */}
        {session?.user ? (
          <div className="space-y-6">
            {/* Impersonation Banner */}
            {impersonatedBy && (
              <ImpersonationBanner
                userName={session.user.name}
                userEmail={session.user.email}
                impersonatedBy={impersonatedBy}
                onStopImpersonating={handleStopImpersonating}
              />
            )}

            {/* Overview KPI Cards */}
            <MetricCards
              session={session}
              userRole={userRole}
              isAdmin={isAdmin}
              saasData={saasData}
              sessionsCount={sessions.length}
              onViewSessions={() => setDashboardTab("sessions")}
            />

            {/* Main Dashboard Navigation Tabs */}
            <Tabs
              value={dashboardTab}
              onValueChange={(val) => {
                setDashboardTab(val);
                if (val === "admin") {
                  loadAdminUsers();
                } else if (val === "sessions") {
                  loadSessions();
                }
              }}
              className="space-y-4"
            >
              <div className="border-b pb-1">
                <TabsList className="h-9">
                  <TabsTrigger value="overview" className="gap-1.5 text-xs px-3">
                    <Activity className="size-3.5" />
                    Overview & Security
                  </TabsTrigger>
                  <TabsTrigger value="sessions" className="gap-1.5 text-xs px-3">
                    <Laptop className="size-3.5" />
                    Active Sessions ({sessions.length})
                  </TabsTrigger>
                  {isAdmin && (
                    <TabsTrigger value="admin" className="gap-1.5 text-xs px-3">
                      <Shield className="size-3.5" />
                      Admin Console ({adminTotal})
                    </TabsTrigger>
                  )}
                  <TabsTrigger value="diagnostics" className="gap-1.5 text-xs px-3">
                    <Terminal className="size-3.5" />
                    API Diagnostics
                  </TabsTrigger>
                </TabsList>
              </div>

              {/* TAB 1: OVERVIEW & SECURITY */}
              <TabsContent value="overview" className="space-y-6">
                <SaasVerificationCard
                  saasData={saasData}
                  isLoading={isLoadingSaas}
                  error={saasError}
                  onRefresh={loadSaasData}
                />
              </TabsContent>

              {/* TAB 2: ACTIVE SESSIONS */}
              <TabsContent value="sessions" className="space-y-6">
                <ActiveSessionsCard
                  sessions={sessions}
                  currentSessionId={saasData?.session?.id || session?.session?.id}
                  onRefresh={loadSessions}
                  onRevokeSession={handleRevokeSession}
                  isLoading={isLoadingSessions}
                />
              </TabsContent>

              {/* TAB 3: ADMIN CONSOLE */}
              {isAdmin && (
                <TabsContent value="admin" className="space-y-6">
                  <AdminConsoleCard
                    users={adminUsers}
                    totalUsers={adminTotal}
                    currentUserId={session.user.id}
                    search={adminSearch}
                    onSearchChange={(q) => {
                      setAdminSearch(q);
                      loadAdminUsers(q);
                    }}
                    onRefresh={() => loadAdminUsers()}
                    isLoading={isLoadingAdmin}
                    onCreateUser={handleCreateUser}
                    onToggleRole={handleToggleRole}
                    onToggleBan={handleToggleBan}
                    onImpersonate={handleImpersonate}
                    onDeleteUser={handleDeleteUser}
                  />
                </TabsContent>
              )}

              {/* TAB 4: API DIAGNOSTICS */}
              <TabsContent value="diagnostics" className="space-y-6">
                <ApiDiagnosticsCard
                  token={getClientToken()}
                  userRole={userRole}
                />
              </TabsContent>
            </Tabs>
          </div>
        ) : (
          /* UNAUTHENTICATED VIEW: HERO + SHADCN AUTH CARD */
          <div className="py-6 sm:py-10 flex flex-col items-center justify-center space-y-8">
            {/* Hero Header */}
            <div className="text-center space-y-2.5 max-w-lg mx-auto">
              <Badge variant="outline" className="gap-1.5 font-mono text-[11px] px-2 py-0.5">
                <Sparkles className="size-3 text-primary" />
                Rust Axum + Better-Auth Protocol
              </Badge>
              <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight font-heading">
                Uni-Auth Web Portal
              </h1>
              <p className="text-xs sm:text-sm text-muted-foreground">
                High-performance authentication client demonstrating multi-session tokens, role-based
                access control, and administrator impersonation against a native Axum backend.
              </p>
            </div>

            {/* In-Page Auth Card */}
            <AuthCard
              authTab={authTab}
              setAuthTab={setAuthTab}
              email={email}
              setEmail={setEmail}
              password={password}
              setPassword={setPassword}
              name={name}
              setName={setName}
              message={message}
              isLoading={isAuthLoading}
              onSignIn={handleSignIn}
              onSignUp={handleSignUp}
              onSocialSignIn={handleSocialSignIn}
              onFillDemo={fillDemoAccount}
            />
          </div>
        )}
      </main>

      {/* 4. MODAL AUTH DIALOG (Can be invoked from header or links) */}
      <AuthDialog
        open={authModalOpen}
        onOpenChange={setAuthModalOpen}
        authTab={authTab}
        setAuthTab={setAuthTab}
        email={email}
        setEmail={setEmail}
        password={password}
        setPassword={setPassword}
        name={name}
        setName={setName}
        message={message}
        isLoading={isAuthLoading}
        onSignIn={handleSignIn}
        onSignUp={handleSignUp}
        onSocialSignIn={handleSocialSignIn}
        onFillDemo={fillDemoAccount}
      />

      {/* 5. APP FOOTER */}
      <footer className="border-t py-4 text-center text-xs text-muted-foreground mt-auto">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-foreground">Uni-Auth</span>
            <span>&bull;</span>
            <span>Axum Backend + Better-Auth Client</span>
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span>Base UI &bull; Tailwind CSS &bull; shadcn</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
