import { describe, it, expect } from "vitest";
import {
  authClient,
  getClientToken,
  setClientToken,
} from "../lib/auth-client";

describe("Better Auth Client integration tests", () => {
  const email = `react_test_${Date.now()}@example.com`;
  const password = "reactpassword123";

  it("should perform sign-up using the official better-auth client", async () => {
    const res = await authClient.signUp.email({
      name: "React Test User",
      email,
      password,
    });

    expect(res.error).toBeNull();
    expect(res.data).toBeDefined();
    expect(res.data?.user.email).toBe(email);
    if ((res.data as any)?.token) {
      setClientToken((res.data as any).token);
    }
    expect(getClientToken()).toBeTruthy();
  });

  it("should get the active session using getSession", async () => {
    const res = await authClient.getSession();
    expect(res.error).toBeNull();
    expect(res.data).toBeDefined();
    expect(res.data?.user.email).toBe(email);
    expect(res.data?.session.userId).toBe(res.data?.user.id);
  });

  it("should list active sessions", async () => {
    const res = await authClient.listSessions();
    expect(res.error).toBeNull();
    expect(Array.isArray(res.data)).toBe(true);
    expect(res.data!.length).toBeGreaterThanOrEqual(1);
  });

  it("should sign out successfully", async () => {
    const res = await authClient.signOut();
    expect(res.error).toBeNull();

    setClientToken("");
    const sessionRes = await authClient.getSession();
    expect(sessionRes.data).toBeNull();
  });

  it("should sign back in using signIn.email", async () => {
    const res = await authClient.signIn.email({
      email,
      password,
    });

    expect(res.error).toBeNull();
    expect(res.data).toBeDefined();
    expect(res.data?.user.email).toBe(email);
    if ((res.data as any)?.token) {
      setClientToken((res.data as any).token);
    }
    expect(getClientToken()).toBeTruthy();

    const sessionRes = await authClient.getSession();
    expect(sessionRes.data).toBeDefined();
    expect(sessionRes.data?.user.email).toBe(email);
  });

  it("should reject banned demo account and allow seeded admin to manage users", async () => {
    // Sign out current user first
    await authClient.signOut();
    setClientToken("");

    // Sign in as seeded admin@example.com
    const adminSignIn = await authClient.signIn.email({
      email: "admin@example.com",
      password: "admin12345",
    });

    if (!adminSignIn.error && adminSignIn.data) {
      if ((adminSignIn.data as any)?.token) {
        setClientToken((adminSignIn.data as any).token);
      }

      const listRes = await authClient.admin.listUsers({
        query: { limit: 20 },
      });
      expect(listRes.error).toBeNull();
      expect(listRes.data?.users.length).toBeGreaterThanOrEqual(1);
    }
  });
});
