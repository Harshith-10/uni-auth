import { createAuthClient } from "better-auth/react";

let authToken = "";
let authCookie = "";

const isNodeTestEnv = typeof window === "undefined";

export const setClientToken = (token: string) => {
  authToken = token;
};

export const getClientToken = () => authToken;

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000/api/auth",
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
      if (isNodeTestEnv) {
        const setCookie = ctx.response.headers.get("set-cookie");
        if (setCookie) {
          if (setCookie.includes("Max-Age=0") || setCookie.includes("expires=Thu, 01 Jan 1970")) {
            authCookie = "";
            authToken = "";
          } else {
            authCookie = setCookie;
          }
        }
      }
    },
  },
});

export const { useSession, signIn, signUp, signOut } = authClient;
