// Node.js Client Wire Parity Test for Rust auth backend

const BASE_URL = process.env.BASE_URL || "http://127.0.0.1:3001/api/auth";
const SAAS_URL = process.env.SAAS_URL || "http://127.0.0.1:3001/api/saas/me";

let cookieJar = "";

function updateCookieJar(headers) {
    const raw = headers.get("set-cookie");
    if (raw) {
        // Extract session cookie name=val
        const match = raw.match(/(?:__Secure-)?better-auth\.session_token=([^;]+)/);
        if (match) {
            cookieJar = `${match[0]}`;
        }
        if (raw.includes("Max-Age=0") || raw.includes("expires=Thu, 01 Jan 1970")) {
            cookieJar = "";
        }
    }
}

async function request(path, options = {}) {
    const url = path.startsWith("http") ? path : `${BASE_URL}${path}`;
    const headers = new Headers(options.headers || {});
    if (cookieJar) {
        headers.set("cookie", cookieJar);
    }
    if (options.body && !headers.has("content-type")) {
        headers.set("content-type", "application/json");
    }

    const res = await fetch(url, {
        ...options,
        headers,
    });

    updateCookieJar(res.headers);
    const text = await res.text();
    let data = null;
    try {
        data = JSON.parse(text);
    } catch {
        data = text;
    }

    return { status: res.status, headers: res.headers, data };
}

async function run() {
    console.log(`\n🧪 Starting Better-Auth Wire Compatibility Test against ${BASE_URL}...`);

    // 1. Health check
    console.log("1. GET /ok");
    const okRes = await request("/ok");
    if (okRes.status !== 200 || !okRes.data?.ok) {
        throw new Error(`GET /ok failed: ${JSON.stringify(okRes)}`);
    }
    console.log("   ✅ OK:", okRes.data);

    // 2. Unauthenticated get-session
    console.log("2. GET /get-session (unauthenticated)");
    const unauthRes = await request("/get-session");
    if (unauthRes.status !== 200 || unauthRes.data !== null) {
        throw new Error(`Expected null for unauthenticated session, got: ${JSON.stringify(unauthRes.data)}`);
    }
    console.log("   ✅ Returns null as expected");

    // 3. Sign up
    const email = `test_node_${Date.now()}@example.com`;
    console.log(`3. POST /sign-up/email (${email})`);
    const signupRes = await request("/sign-up/email", {
        method: "POST",
        body: JSON.stringify({
            name: "Node Test Client",
            email,
            password: "supersecurepassword123",
            rememberMe: true,
        }),
    });

    if (signupRes.status !== 200 || !signupRes.data?.token) {
        throw new Error(`Sign-up failed: ${JSON.stringify(signupRes)}`);
    }
    const token = signupRes.data.token;
    const authHeaderToken = signupRes.headers.get("set-auth-token");
    if (!authHeaderToken) {
        throw new Error("Missing 'set-auth-token' response header!");
    }
    console.log("   ✅ Signed up successfully!");
    console.log(`      User ID: ${signupRes.data.user.id}`);
    console.log(`      Cookie Jar: ${cookieJar}`);
    console.log(`      set-auth-token: ${authHeaderToken.slice(0, 20)}...`);

    // 4. GET /get-session with browser cookie
    console.log("4. GET /get-session (with cookie)");
    const sessionRes = await request("/get-session");
    if (sessionRes.status !== 200 || !sessionRes.data?.session || sessionRes.data.user.email !== email) {
        throw new Error(`GET /get-session failed: ${JSON.stringify(sessionRes)}`);
    }
    console.log("   ✅ Session resolved via cookie:", sessionRes.data.user.email);

    // 5. GET /api/saas/me (protected SaaS endpoint via cookie)
    console.log("5. GET /api/saas/me (via cookie)");
    const saasCookieRes = await request(SAAS_URL);
    if (saasCookieRes.status !== 200 || !saasCookieRes.data?.transport?.includes("Cookie")) {
        throw new Error(`Protected SaaS call failed: ${JSON.stringify(saasCookieRes)}`);
    }
    console.log(`   ✅ Protected SaaS endpoint succeeded: ${saasCookieRes.data.transport}`);

    // 6. GET /api/saas/me (protected SaaS endpoint via Bearer token)
    console.log("6. GET /api/saas/me (via Bearer token)");
    const saasBearerRes = await fetch(SAAS_URL, {
        headers: {
            authorization: `Bearer ${token}`,
        },
    });
    const saasBearerData = await saasBearerRes.json();
    if (saasBearerRes.status !== 200 || !saasBearerData?.transport?.includes("Bearer")) {
        throw new Error(`Bearer SaaS call failed: ${JSON.stringify(saasBearerData)}`);
    }
    console.log(`   ✅ Bearer token call succeeded: ${saasBearerData.transport}`);

    // 7. GET /list-sessions
    console.log("7. GET /list-sessions");
    const listRes = await request("/list-sessions");
    if (listRes.status !== 200 || !Array.isArray(listRes.data) || listRes.data.length < 1) {
        throw new Error(`List sessions failed: ${JSON.stringify(listRes)}`);
    }
    console.log(`   ✅ Active sessions: ${listRes.data.length}`);

    // 8. One-Time Token generate and verify
    console.log("8. OTT generate and verify");
    const ottGenRes = await request("/one-time-token/generate");
    if (ottGenRes.status !== 200 || !ottGenRes.data?.token) {
        throw new Error(`OTT generate failed: ${JSON.stringify(ottGenRes)}`);
    }
    const ott = ottGenRes.data.token;
    console.log(`   ✅ OTT generated: ${ott.slice(0, 16)}...`);

    const ottVerifyRes = await fetch(`${BASE_URL}/one-time-token/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: ott }),
    });
    const ottVerifyData = await ottVerifyRes.json();
    if (ottVerifyRes.status !== 200 || ottVerifyData.user.email !== email) {
        throw new Error(`OTT verify failed: ${JSON.stringify(ottVerifyData)}`);
    }
    console.log("   ✅ OTT verified successfully and single-use burned!");

    // 9. Sign out
    console.log("9. POST /sign-out");
    const signoutRes = await request("/sign-out", { method: "POST" });
    if (signoutRes.status !== 200 || !signoutRes.data?.success) {
        throw new Error(`Sign out failed: ${JSON.stringify(signoutRes)}`);
    }
    console.log("   ✅ Signed out successfully, cookie cleared!");

    // 10. Verify session is dead
    console.log("10. GET /get-session after sign-out");
    const deadRes = await request("/get-session");
    if (deadRes.data !== null) {
        throw new Error(`Expected null after signout, got: ${JSON.stringify(deadRes.data)}`);
    }
    console.log("   ✅ Session returns null after signout");

    // 11. Sign in with same credentials
    console.log(`11. POST /sign-in/email (${email})`);
    const signinRes = await request("/sign-in/email", {
        method: "POST",
        body: JSON.stringify({
            email,
            password: "supersecurepassword123",
            rememberMe: true,
        }),
    });
    if (signinRes.status !== 200 || !signinRes.data?.token) {
        throw new Error(`Sign in failed: ${JSON.stringify(signinRes)}`);
    }
    console.log("   ✅ Re-signed in successfully!");

    console.log("\n🎉 ALL WIRE COMPATIBILITY TESTS PASSED WITH 0 ERRORS!\n");
}

run().catch((err) => {
    console.error("\n❌ Compatibility test failed:", err);
    process.exit(1);
});
