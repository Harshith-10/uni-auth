import React, { useState, useEffect } from "react";
import { authClient, useSession, getClientToken } from "./lib/auth-client";
import { Alert, AlertDescription, AlertTitle } from "./components/ui/alert";
import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./components/ui/card";
import { Input } from "./components/ui/input";
import { Label } from "./components/ui/label";
import { Separator } from "./components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./components/ui/tabs";

export function App() {
  const { data: session, isPending, refetch: refetchSession } = useSession();
  const [authTab, setAuthTab] = useState<string>("signin");
  const [dashboardTab, setDashboardTab] = useState<string>("overview");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [message, setMessage] = useState<{
    type: "default" | "destructive";
    text: string;
  } | null>(null);

  const [saasData, setSaasData] = useState<any>(null);
  const [isLoadingSaas, setIsLoadingSaas] = useState(false);
  const [saasError, setSaasError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<any[]>([]);

  // Admin state
  const [adminUsers, setAdminUsers] = useState<any[]>([]);
  const [adminTotal, setAdminTotal] = useState<number>(0);
  const [adminSearch, setAdminSearch] = useState("");
  const [isLoadingAdmin, setIsLoadingAdmin] = useState(false);

  const [newUserName, setNewUserName] = useState("");
  const [newUserEmail, setNewUserEmail] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [newUserRole, setNewUserRole] = useState<"user" | "admin">("user");
  const [isCreatingUser, setIsCreatingUser] = useState(false);

  const userRole = (session?.user as any)?.role || "user";
  const isAdmin = String(userRole)
    .split(",")
    .some((r) => r.trim() === "admin");
  const impersonatedBy = (session?.session as any)?.impersonatedBy as
    | string
    | null
    | undefined;

  useEffect(() => {
    if (session?.user) {
      loadSessions();
      loadSaasData();
      if (isAdmin) {
        loadAdminUsers();
      }
    }
  }, [session?.user?.id, userRole, impersonatedBy]);

  const loadSessions = async () => {
    try {
      const res = await authClient.listSessions();
      if (res.data) {
        setSessions(res.data);
      }
    } catch (e: any) {
      console.error("Failed to load sessions:", e);
    }
  };

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

  const fillDemoAccount = (demoEmail: string, demoPassword: string) => {
    setAuthTab("signin");
    setEmail(demoEmail);
    setPassword(demoPassword);
    setMessage(null);
  };

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage({ type: "default", text: "Creating account..." });
    const res = await authClient.signUp.email({
      name,
      email,
      password,
    });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Sign up failed",
      });
    } else {
      setMessage(null);
      await refetchSession();
    }
  };

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage({ type: "default", text: "Signing in..." });
    const res = await authClient.signIn.email({
      email,
      password,
    });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Sign in failed",
      });
    } else {
      setMessage(null);
      await refetchSession();
    }
  };

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

  const handleSignOut = async () => {
    await authClient.signOut();
    setSaasData(null);
    setSessions([]);
    setAdminUsers([]);
    setDashboardTab("overview");
    setMessage(null);
  };

  const handleRevokeSession = async (token: string) => {
    await authClient.revokeSession({ token });
    loadSessions();
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUserEmail.trim() || !newUserPassword) return;
    setIsCreatingUser(true);
    try {
      const res = await authClient.admin.createUser({
        name: newUserName.trim() || newUserEmail.split("@")[0],
        email: newUserEmail.trim(),
        password: newUserPassword,
        role: newUserRole,
      });
      if (res.error) {
        setMessage({
          type: "destructive",
          text: res.error.message || "Failed to create user",
        });
      } else {
        setNewUserName("");
        setNewUserEmail("");
        setNewUserPassword("");
        setMessage({
          type: "default",
          text: `Created user ${res.data?.user?.email}`,
        });
        await loadAdminUsers();
      }
    } finally {
      setIsCreatingUser(false);
    }
  };

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
      await loadAdminUsers();
    }
  };

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
        text: res.error.message || "Failed to update ban state",
      });
    } else {
      await loadAdminUsers();
    }
  };

  const handleImpersonate = async (userId: string) => {
    const res = await authClient.admin.impersonateUser({ userId });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to impersonate user",
      });
    } else {
      setDashboardTab("overview");
      await refetchSession();
      await loadSaasData();
      await loadSessions();
    }
  };

  const handleStopImpersonating = async () => {
    const res = await authClient.admin.stopImpersonating();
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to stop impersonating",
      });
    } else {
      await refetchSession();
      await loadSaasData();
      await loadSessions();
    }
  };

  const handleDeleteUser = async (userId: string) => {
    const res = await authClient.admin.removeUser({ userId });
    if (res.error) {
      setMessage({
        type: "destructive",
        text: res.error.message || "Failed to remove user",
      });
    } else {
      await loadAdminUsers();
    }
  };

  if (isPending) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6">
        <p className="text-sm text-muted-foreground">
          Loading authentication state...
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground py-8 px-4">
      <div className="max-w-4xl mx-auto space-y-6">
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b">
          <div className="space-y-1">
            <h1 className="text-2xl font-bold tracking-tight">
              uni-auth Web Demo
            </h1>
            <p className="text-sm text-muted-foreground">
              Better-Auth React Client + Admin Plugin running against Rust Axum
              Backend
            </p>
          </div>
          {session?.user && (
            <div className="flex items-center gap-2">
              <Badge variant={isAdmin ? "default" : "secondary"}>
                Role: {userRole}
              </Badge>
              <Button variant="destructive" size="sm" onClick={handleSignOut}>
                Sign Out
              </Button>
            </div>
          )}
        </header>

        {message && (
          <Alert variant={message.type}>
            <AlertDescription>{message.text}</AlertDescription>
          </Alert>
        )}

        {session?.user ? (
          <div className="space-y-6">
            {impersonatedBy && (
              <Alert>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <AlertTitle>
                      Impersonating {session.user.name} ({session.user.email})
                    </AlertTitle>
                    <AlertDescription className="text-muted-foreground">
                      Original Admin ID: {impersonatedBy}
                    </AlertDescription>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleStopImpersonating}
                  >
                    Stop Impersonating
                  </Button>
                </div>
              </Alert>
            )}

            <Tabs
              value={dashboardTab}
              onValueChange={(val) => {
                setDashboardTab(val);
                if (val === "admin") {
                  loadAdminUsers();
                }
              }}
            >
              <TabsList>
                <TabsTrigger value="overview">Account & Sessions</TabsTrigger>
                {isAdmin && (
                  <TabsTrigger value="admin">
                    Admin Console ({adminTotal})
                  </TabsTrigger>
                )}
              </TabsList>

              <TabsContent value="overview" className="space-y-6">
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between">
                    <div className="space-y-1">
                      <CardTitle>Welcome, {session.user.name}!</CardTitle>
                      <CardDescription>{session.user.email}</CardDescription>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={loadSaasData}
                      disabled={isLoadingSaas}
                    >
                      {isLoadingSaas ? "Refreshing..." : "Refresh /api/saas/me"}
                    </Button>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {saasError && (
                      <Alert variant="destructive">
                        <AlertTitle>Error fetching /api/saas/me</AlertTitle>
                        <AlertDescription>{saasError}</AlertDescription>
                      </Alert>
                    )}

                    {saasData && (
                      <div className="space-y-4">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">
                            Transport:
                          </span>
                          <Badge variant="outline">{saasData.transport}</Badge>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 rounded-lg bg-muted p-4 text-sm">
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">
                              Status:
                            </span>
                            <span className="font-medium">
                              {saasData.status}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">
                              Email Verified:
                            </span>
                            <span className="font-medium">
                              {saasData.user?.emailVerified ? "Yes" : "No"}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">
                              Session ID:
                            </span>
                            <span className="font-mono text-xs">
                              {saasData.session?.id
                                ? `${saasData.session.id.slice(0, 12)}...`
                                : "N/A"}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">
                              Expires:
                            </span>
                            <span className="text-xs">
                              {saasData.session?.expiresAt
                                ? new Date(
                                    saasData.session.expiresAt
                                  ).toLocaleTimeString()
                                : "N/A"}
                            </span>
                          </div>
                        </div>

                        <details className="rounded-lg border p-3 text-xs">
                          <summary className="cursor-pointer font-medium text-muted-foreground">
                            View Raw /api/saas/me JSON Payload
                          </summary>
                          <pre className="mt-2 overflow-x-auto font-mono text-xs p-2 rounded-md bg-muted">
                            {JSON.stringify(saasData, null, 2)}
                          </pre>
                        </details>
                      </div>
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="flex flex-row items-center justify-between">
                    <div className="space-y-1">
                      <CardTitle>Active Sessions ({sessions.length})</CardTitle>
                      <CardDescription>
                        Manage active devices signed in to your account
                      </CardDescription>
                    </div>
                    <Button variant="outline" size="sm" onClick={loadSessions}>
                      Refresh
                    </Button>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Session</TableHead>
                          <TableHead>User Agent</TableHead>
                          <TableHead>Expires</TableHead>
                          <TableHead className="text-right">Action</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {sessions.map((s, idx) => {
                          const isCurrent = s.id === saasData?.session?.id;
                          return (
                            <TableRow key={s.id || idx}>
                              <TableCell className="font-mono text-xs">
                                <div className="flex items-center gap-2">
                                  <span>{s.id?.slice(0, 8)}...</span>
                                  {isCurrent && (
                                    <Badge variant="secondary">Current</Badge>
                                  )}
                                </div>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {s.userAgent || "Web Browser"}
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {new Date(s.expiresAt).toLocaleString()}
                              </TableCell>
                              <TableCell className="text-right">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => handleRevokeSession(s.token)}
                                >
                                  Revoke
                                </Button>
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </TabsContent>

              {isAdmin && (
                <TabsContent value="admin" className="space-y-6">
                  <Card>
                    <CardHeader>
                      <CardTitle>Create User</CardTitle>
                      <CardDescription>
                        Provision a new account via the Better-Auth Admin plugin
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <form
                        onSubmit={handleCreateUser}
                        className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-center"
                      >
                        <Input
                          placeholder="Full name"
                          value={newUserName}
                          onChange={(e) => setNewUserName(e.target.value)}
                        />
                        <Input
                          type="email"
                          placeholder="user@example.com"
                          value={newUserEmail}
                          onChange={(e) => setNewUserEmail(e.target.value)}
                          required
                        />
                        <Input
                          type="password"
                          placeholder="Initial password"
                          value={newUserPassword}
                          onChange={(e) => setNewUserPassword(e.target.value)}
                          required
                        />
                        <div className="flex gap-2">
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() =>
                              setNewUserRole(
                                newUserRole === "admin" ? "user" : "admin"
                              )
                            }
                          >
                            Role: {newUserRole}
                          </Button>
                          <Button type="submit" disabled={isCreatingUser}>
                            {isCreatingUser ? "Creating..." : "Create"}
                          </Button>
                        </div>
                      </form>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="flex flex-row items-center justify-between gap-4">
                      <div className="space-y-1">
                        <CardTitle>Users Directory ({adminTotal})</CardTitle>
                        <CardDescription>
                          Inspect roles, ban status, and impersonate accounts
                        </CardDescription>
                      </div>
                      <div className="flex items-center gap-2">
                        <Input
                          placeholder="Search by email..."
                          value={adminSearch}
                          onChange={(e) => {
                            setAdminSearch(e.target.value);
                            loadAdminUsers(e.target.value);
                          }}
                        />
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => loadAdminUsers()}
                          disabled={isLoadingAdmin}
                        >
                          {isLoadingAdmin ? "Loading..." : "Refresh"}
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>User</TableHead>
                            <TableHead>Role</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead className="text-right">
                              Actions
                            </TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {adminUsers.map((u) => {
                            const isSelf = u.id === session.user.id;
                            const uRole = u.role || "user";
                            const uBanned = Boolean(u.banned);
                            return (
                              <TableRow key={u.id}>
                                <TableCell>
                                  <div className="font-medium">{u.name}</div>
                                  <div className="text-xs text-muted-foreground">
                                    {u.email}
                                  </div>
                                </TableCell>
                                <TableCell>
                                  <Badge
                                    variant={
                                      uRole === "admin"
                                        ? "default"
                                        : "secondary"
                                    }
                                  >
                                    {uRole}
                                  </Badge>
                                </TableCell>
                                <TableCell>
                                  <div className="flex items-center gap-1.5">
                                    {uBanned ? (
                                      <Badge variant="destructive">
                                        Banned
                                      </Badge>
                                    ) : (
                                      <Badge variant="outline">Active</Badge>
                                    )}
                                    {u.emailVerified && (
                                      <Badge variant="secondary">
                                        Verified
                                      </Badge>
                                    )}
                                  </div>
                                </TableCell>
                                <TableCell className="text-right">
                                  <div className="flex items-center justify-end gap-2">
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      onClick={() =>
                                        handleToggleRole(u.id, uRole)
                                      }
                                    >
                                      {uRole === "admin"
                                        ? "Set User"
                                        : "Make Admin"}
                                    </Button>
                                    {!isSelf && (
                                      <>
                                        <Button
                                          variant="outline"
                                          size="sm"
                                          onClick={() =>
                                            handleToggleBan(u.id, uBanned)
                                          }
                                        >
                                          {uBanned ? "Unban" : "Ban"}
                                        </Button>
                                        {!uBanned && (
                                          <Button
                                            variant="secondary"
                                            size="sm"
                                            onClick={() =>
                                              handleImpersonate(u.id)
                                            }
                                          >
                                            Impersonate
                                          </Button>
                                        )}
                                        <Button
                                          variant="destructive"
                                          size="sm"
                                          onClick={() => handleDeleteUser(u.id)}
                                        >
                                          Delete
                                        </Button>
                                      </>
                                    )}
                                  </div>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </TabsContent>
              )}
            </Tabs>
          </div>
        ) : (
          <div className="max-w-md mx-auto">
            <Card>
              <CardHeader>
                <CardTitle>Authentication</CardTitle>
                <CardDescription>
                  Sign in with a seeded demo account or create a new user
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Tabs value={authTab} onValueChange={setAuthTab}>
                  <TabsList className="w-full">
                    <TabsTrigger value="signin" className="flex-1">
                      Sign In
                    </TabsTrigger>
                    <TabsTrigger value="signup" className="flex-1">
                      Sign Up
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="signin" className="space-y-4">
                    <form onSubmit={handleSignIn} className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="signin-email">Email</Label>
                        <Input
                          id="signin-email"
                          type="email"
                          placeholder="admin@example.com"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          required
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="signin-password">Password</Label>
                        <Input
                          id="signin-password"
                          type="password"
                          placeholder="••••••••"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          required
                        />
                      </div>
                      <Button type="submit" className="w-full">
                        Sign In
                      </Button>
                    </form>
                  </TabsContent>

                  <TabsContent value="signup" className="space-y-4">
                    <form onSubmit={handleSignUp} className="space-y-4">
                      <div className="space-y-2">
                        <Label htmlFor="signup-name">Full Name</Label>
                        <Input
                          id="signup-name"
                          type="text"
                          placeholder="Ada Lovelace"
                          value={name}
                          onChange={(e) => setName(e.target.value)}
                          required
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="signup-email">Email</Label>
                        <Input
                          id="signup-email"
                          type="email"
                          placeholder="ada@example.com"
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                          required
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="signup-password">Password</Label>
                        <Input
                          id="signup-password"
                          type="password"
                          placeholder="••••••••"
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          required
                        />
                      </div>
                      <Button type="submit" className="w-full">
                        Create Account
                      </Button>
                    </form>
                  </TabsContent>
                </Tabs>

                <Separator />

                <div className="space-y-2 rounded-lg bg-muted p-3">
                  <p className="text-xs font-medium text-muted-foreground">
                    Seeded Demo Accounts (click to fill)
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        fillDemoAccount("admin@example.com", "admin12345")
                      }
                    >
                      Admin
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        fillDemoAccount("alice@example.com", "password123")
                      }
                    >
                      Alice (User)
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        fillDemoAccount("bob@example.com", "password123")
                      }
                    >
                      Bob (Unverified)
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        fillDemoAccount("banned@example.com", "password123")
                      }
                    >
                      Banned
                    </Button>
                  </div>
                </div>

                <Separator />

                <div className="grid grid-cols-2 gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => handleSocialSignIn("google")}
                  >
                    Google
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => handleSocialSignIn("github")}
                  >
                    GitHub
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
