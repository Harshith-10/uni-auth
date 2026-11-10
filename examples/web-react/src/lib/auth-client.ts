import { createAuthClient } from "better-auth/react";
import { adminClient } from "better-auth/client/plugins";

let authToken = "";
let adminAuthToken = "";
let authCookie = "";

const isNodeTestEnv = typeof window === "undefined";

export const setClientToken = (token: string) => {
  authToken = token;
};

export const getClientToken = () => authToken;

export const setAdminClientToken = (token: string) => {
  adminAuthToken = token;
};

export const getAdminClientToken = () => adminAuthToken;

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000/api/auth",
  plugins: [adminClient()],
  fetchOptions: {
    credentials: "include",
    auth: {
      type: "Bearer",
      token: () => authToken,
    },
    onRequest: (ctx) => {
      if (authToken) {
        ctx.headers.set("authorization", `Bearer ${authToken}`);
      }
      if (adminAuthToken) {
        ctx.headers.set("x-admin-auth-token", adminAuthToken);
      }
      if (isNodeTestEnv && authCookie) {
        ctx.headers.set("cookie", authCookie);
      }
      return ctx;
    },
    onResponse: (ctx) => {
      const setAuthToken = ctx.response.headers.get("set-auth-token");
      if (setAuthToken) {
        authToken = setAuthToken;
      }
      if (ctx.response.headers.has("set-admin-auth-token")) {
        const setAdminToken =
          ctx.response.headers.get("set-admin-auth-token") ?? "";
        adminAuthToken = setAdminToken;
      }
      if (isNodeTestEnv) {
        const setCookie = ctx.response.headers.get("set-cookie");
        if (setCookie) {
          if (
            setCookie.includes("Max-Age=0") &&
            !setCookie.includes("better-auth.session_token=v") &&
            !ctx.response.headers.get("set-auth-token")
          ) {
            authCookie = "";
            authToken = "";
            adminAuthToken = "";
          } else {
            authCookie = setCookie;
          }
        }
      }
    },
  },
});

export const { useSession, signIn, signUp, signOut } = authClient;
