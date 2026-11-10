import React, { useState, useEffect } from "react";
import { authClient, useSession, getClientToken } from "./lib/auth-client";

export function App() {
  const { data: session, isPending } = useSession();
  const [tab, setTab] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [saasData, setSaasData] = useState<any>(null);
  const [isLoadingSaas, setIsLoadingSaas] = useState(false);
  const [saasError, setSaasError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<any[]>([]);

  useEffect(() => {
    if (session?.user) {
      loadSessions();
      loadSaasData();
    }
  }, [session]);

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
      const host = window.location.hostname === "127.0.0.1" ? "127.0.0.1" : "localhost";
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
      console.error("Failed to call SaaS endpoint:", e);
      setSaasError(e?.message || "Failed to reach SaaS endpoint");
    } finally {
      setIsLoadingSaas(false);
    }
  };

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage("Signing up...");
    const res = await authClient.signUp.email({
      name,
      email,
      password,
    });
    if (res.error) {
      setMessage(`Error: ${res.error.message || "Sign up failed"}`);
    } else {
      setMessage("Signed up successfully!");
    }
  };

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage("Signing in...");
    const res = await authClient.signIn.email({
      email,
      password,
    });
    if (res.error) {
      setMessage(`Error: ${res.error.message || "Sign in failed"}`);
    } else {
      setMessage("Signed in successfully!");
    }
  };

  const handleSocialSignIn = async (provider: "google" | "github") => {
    setMessage(`Redirecting to ${provider}...`);
    try {
      await authClient.signIn.social({
        provider,
        callbackURL: window.location.origin,
      });
    } catch (err: any) {
      setMessage(`Error: ${err?.message || "Social sign-in failed"}`);
    }
  };

  const handleSignOut = async () => {
    await authClient.signOut();
    setSaasData(null);
    setSessions([]);
    setMessage("Signed out.");
  };

  const handleRevokeSession = async (token: string) => {
    await authClient.revokeSession({ token });
    loadSessions();
  };

  if (isPending) {
    return <div style={{ color: "#94a3b8" }}>Loading authentication status...</div>;
  }

  return (
    <div style={{ maxWidth: 680, margin: "0 auto", textAlign: "left", fontFamily: "system-ui, -apple-system, sans-serif" }}>
      <header style={{ marginBottom: "2rem", borderBottom: "1px solid #334155", paddingBottom: "1rem" }}>
        <h1 style={{ margin: "0 0 0.5rem", color: "#38bdf8" }}>uni-auth Web Demo</h1>
        <p style={{ margin: 0, color: "#94a3b8" }}>
          Better-Auth React Client running against Rust Axum Backend
        </p>
      </header>

      {session?.user ? (
        <div style={{ background: "#1e293b", padding: "1.5rem", borderRadius: 8, border: "1px solid #334155" }}>
          {/* Header & Sign Out */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <h2 style={{ margin: 0, color: "#f8fafc" }}>Welcome, {session.user.name}!</h2>
              <p style={{ margin: "0.25rem 0 0", color: "#94a3b8", fontSize: "0.9rem" }}>{session.user.email}</p>
            </div>
            <button
              onClick={handleSignOut}
              style={{
                background: "#ef4444",
                color: "white",
                border: "none",
                padding: "0.5rem 1rem",
                borderRadius: 6,
                cursor: "pointer",
                fontWeight: 600,
                fontSize: "0.85rem",
              }}
            >
              Sign Out
            </button>
          </div>

          {/* Protected SaaS /api/saas/me Endpoint Section */}
          <div style={{ marginTop: "1.5rem", padding: "1.25rem", background: "#0f172a", borderRadius: 8, border: "1px solid #334155" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: saasData ? "#10b981" : "#eab308" }} />
                <h3 style={{ margin: 0, fontSize: "1rem", color: "#38bdf8" }}>Protected API: <code>/api/saas/me</code></h3>
              </div>
              <button
                onClick={loadSaasData}
                disabled={isLoadingSaas}
                style={{
                  background: "#1e293b",
                  color: "#94a3b8",
                  border: "1px solid #475569",
                  padding: "0.3rem 0.75rem",
                  borderRadius: 4,
                  cursor: isLoadingSaas ? "not-allowed" : "pointer",
                  fontSize: "0.8rem",
                }}
              >
                {isLoadingSaas ? "Loading..." : "Refresh"}
              </button>
            </div>

            {saasError && (
              <div style={{ padding: "0.75rem", background: "#450a0a", border: "1px solid #991b1b", borderRadius: 6, color: "#fca5a5", fontSize: "0.85rem", marginBottom: "0.75rem" }}>
                <strong>Error fetching /api/saas/me:</strong> {saasError}
              </div>
            )}

            {saasData ? (
              <div>
                {/* Transport Badge */}
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
                  <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>Transport:</span>
                  <span
                    style={{
                      background: saasData.transport?.includes("Cookie") ? "#064e3b" : "#1e3a8a",
                      color: saasData.transport?.includes("Cookie") ? "#34d399" : "#60a5fa",
                      border: `1px solid ${saasData.transport?.includes("Cookie") ? "#059669" : "#2563eb"}`,
                      padding: "0.2rem 0.6rem",
                      borderRadius: 4,
                      fontSize: "0.8rem",
                      fontWeight: 600,
                    }}
                  >
                    {saasData.transport}
                  </span>
                </div>

                {/* Grid of Key Properties */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", background: "#1e293b", padding: "0.75rem", borderRadius: 6, fontSize: "0.85rem", marginBottom: "0.75rem" }}>
                  <div>
                    <span style={{ color: "#64748b" }}>Status: </span>
                    <strong style={{ color: "#10b981" }}>{saasData.status}</strong>
                  </div>
                  <div>
                    <span style={{ color: "#64748b" }}>Email Verified: </span>
                    <strong style={{ color: saasData.user?.emailVerified ? "#10b981" : "#f59e0b" }}>
                      {saasData.user?.emailVerified ? "Yes" : "No"}
                    </strong>
                  </div>
                  <div>
                    <span style={{ color: "#64748b" }}>Session ID: </span>
                    <code style={{ color: "#cbd5e1" }}>{saasData.session?.id ? `${saasData.session.id.slice(0, 12)}...` : "N/A"}</code>
                  </div>
                  <div>
                    <span style={{ color: "#64748b" }}>Session Expires: </span>
                    <span style={{ color: "#cbd5e1" }}>{saasData.session?.expiresAt ? new Date(saasData.session.expiresAt).toLocaleTimeString() : "N/A"}</span>
                  </div>
                </div>

                {/* Raw JSON Payload */}
                <details style={{ background: "#020617", padding: "0.5rem 0.75rem", borderRadius: 6, border: "1px solid #1e293b" }}>
                  <summary style={{ cursor: "pointer", color: "#64748b", fontSize: "0.8rem", fontWeight: 500 }}>
                    View Raw Server Response JSON
                  </summary>
                  <pre style={{ margin: "0.5rem 0 0", padding: "0.5rem", fontSize: "0.75rem", color: "#a5f3fc", overflowX: "auto" }}>
                    {JSON.stringify(saasData, null, 2)}
                  </pre>
                </details>
              </div>
            ) : (
              !saasError && (
                <div style={{ color: "#64748b", fontSize: "0.85rem", fontStyle: "italic" }}>
                  {isLoadingSaas ? "Fetching /api/saas/me from Axum server..." : "No data available."}
                </div>
              )
            )}
          </div>

          {/* Active Sessions List */}
          <div style={{ marginTop: "1.5rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
              <h3 style={{ margin: 0, fontSize: "1.1rem", color: "#f8fafc" }}>Active Sessions ({sessions.length})</h3>
              <button
                onClick={loadSessions}
                style={{
                  background: "#0f172a",
                  color: "#94a3b8",
                  border: "1px solid #334155",
                  padding: "0.25rem 0.5rem",
                  borderRadius: 4,
                  cursor: "pointer",
                  fontSize: "0.8rem",
                }}
              >
                Refresh
              </button>
            </div>

            {sessions.map((s, idx) => (
              <div
                key={s.id || idx}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "0.75rem",
                  background: "#0f172a",
                  borderRadius: 6,
                  marginBottom: "0.5rem",
                  fontSize: "0.85rem",
                  border: s.id === saasData?.session?.id ? "1px solid #0284c7" : "1px solid transparent",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span style={{ color: "#f8fafc", fontFamily: "monospace" }}>ID: {s.id?.slice(0, 8)}...</span>
                    {s.id === saasData?.session?.id && (
                      <span style={{ background: "#0369a1", color: "#e0f2fe", fontSize: "0.7rem", padding: "0.1rem 0.4rem", borderRadius: 4 }}>
                        Current
                      </span>
                    )}
                  </div>
                  <div style={{ color: "#64748b", fontSize: "0.75rem", marginTop: "0.2rem" }}>
                    User Agent: {s.userAgent || "Web Browser"} | Expires: {new Date(s.expiresAt).toLocaleString()}
                  </div>
                </div>
                <button
                  onClick={() => handleRevokeSession(s.token)}
                  style={{
                    background: "#475569",
                    color: "white",
                    border: "none",
                    padding: "0.3rem 0.6rem",
                    borderRadius: 4,
                    cursor: "pointer",
                    fontSize: "0.8rem",
                  }}
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div style={{ background: "#1e293b", padding: "1.5rem", borderRadius: 8, border: "1px solid #334155" }}>
          <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
            <button
              onClick={() => setTab("signin")}
              style={{
                background: tab === "signin" ? "#38bdf8" : "transparent",
                color: tab === "signin" ? "#0f172a" : "#94a3b8",
                border: "1px solid #334155",
                padding: "0.5rem 1rem",
                borderRadius: 4,
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              Sign In
            </button>
            <button
              onClick={() => setTab("signup")}
              style={{
                background: tab === "signup" ? "#38bdf8" : "transparent",
                color: tab === "signup" ? "#0f172a" : "#94a3b8",
                border: "1px solid #334155",
                padding: "0.5rem 1rem",
                borderRadius: 4,
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              Sign Up
            </button>
          </div>

          <form onSubmit={tab === "signin" ? handleSignIn : handleSignUp} style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            {tab === "signup" && (
              <div>
                <label style={{ display: "block", marginBottom: "0.25rem", color: "#94a3b8", fontSize: "0.85rem" }}>Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  style={{ width: "100%", padding: "0.5rem", borderRadius: 4, border: "1px solid #334155", background: "#0f172a", color: "white" }}
                />
              </div>
            )}
            <div>
              <label style={{ display: "block", marginBottom: "0.25rem", color: "#94a3b8", fontSize: "0.85rem" }}>Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                style={{ width: "100%", padding: "0.5rem", borderRadius: 4, border: "1px solid #334155", background: "#0f172a", color: "white" }}
              />
            </div>
            <div>
              <label style={{ display: "block", marginBottom: "0.25rem", color: "#94a3b8", fontSize: "0.85rem" }}>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                style={{ width: "100%", padding: "0.5rem", borderRadius: 4, border: "1px solid #334155", background: "#0f172a", color: "white" }}
              />
            </div>
            <button
              type="submit"
              style={{
                marginTop: "0.5rem",
                background: "#10b981",
                color: "white",
                border: "none",
                padding: "0.6rem",
                borderRadius: 4,
                cursor: "pointer",
                fontWeight: 600,
              }}
            >
              {tab === "signin" ? "Sign In" : "Create Account"}
            </button>
          </form>

          <div style={{ marginTop: "1.25rem", paddingTop: "1.25rem", borderTop: "1px solid #334155", display: "flex", flexDirection: "column", gap: "0.6rem" }}>
            <div style={{ textAlign: "center", color: "#64748b", fontSize: "0.8rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Or continue with
            </div>
            <button
              type="button"
              onClick={() => handleSocialSignIn("google")}
              style={{
                background: "#ffffff",
                color: "#1f2937",
                border: "1px solid #cbd5e1",
                padding: "0.6rem",
                borderRadius: 4,
                cursor: "pointer",
                fontWeight: 600,
                fontSize: "0.9rem",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "0.6rem",
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
              </svg>
              Continue with Google
            </button>
            <button
              type="button"
              onClick={() => handleSocialSignIn("github")}
              style={{
                background: "#24292e",
                color: "#ffffff",
                border: "1px solid #475569",
                padding: "0.6rem",
                borderRadius: 4,
                cursor: "pointer",
                fontWeight: 600,
                fontSize: "0.9rem",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "0.6rem",
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              Continue with GitHub
            </button>
          </div>

          {message && (
            <p style={{ marginTop: "1rem", color: message.startsWith("Error") ? "#ef4444" : "#10b981", fontSize: "0.9rem" }}>
              {message}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
