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
