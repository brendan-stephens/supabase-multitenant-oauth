import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { SignJWT, importPKCS8, importJWK, jwtVerify } from "npm:jose@5";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const ISSUER = `${SUPABASE_URL}/functions/v1/oidc`;

// SUPABASE_ANON_KEY is auto-injected by the Edge Runtime and used for user-level
// auth operations (signInWithPassword). The publishable key (sb_publishable_*)
// is the intended long-term replacement but requires supabase-js >=2.45 — until
// the runtime pins a version that ships it, use the injected anon key here.
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

let _privKey: CryptoKey | undefined;
let _pubKey: CryptoKey | undefined;

async function getPrivKey(): Promise<CryptoKey> {
  if (!_privKey) {
    _privKey = await importPKCS8(Deno.env.get("OAUTH_PRIVATE_KEY")!, "RS256") as CryptoKey;
  }
  return _privKey;
}

async function getPubKey(): Promise<CryptoKey> {
  if (!_pubKey) {
    const jwk = JSON.parse(Deno.env.get("OAUTH_PUBLIC_KEY_JWK")!);
    _pubKey = await importJWK(jwk, "RS256") as CryptoKey;
  }
  return _pubKey;
}

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

function db() {
  return createClient(SUPABASE_URL, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });

  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/oidc/, "") || "/";

  try {
    if (path === "/.well-known/openid-configuration") return discovery();
    if (path === "/jwks") return jwks();
    if (req.method === "GET" && path === "/authorize") return await authorizeGet(url);
    if (req.method === "POST" && path === "/authorize") return await authorizePost(req, url);
    if (req.method === "POST" && path === "/token") return await token(req);
    if (path === "/userinfo") return await userinfo(req);
    if (req.method === "GET" && path === "/signup") return await signupGet(url);
    if (req.method === "POST" && path === "/signup") return await signupPost(req, url);
    return new Response("Not Found", { status: 404, headers: cors });
  } catch (e) {
    console.error("[oidc]", e);
    return Response.json({ error: "server_error", detail: String(e) }, { status: 500, headers: cors });
  }
});

function discovery() {
  return Response.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    jwks_uri: `${ISSUER}/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "email", "profile"],
    claims_supported: ["sub", "email", "email_verified"],
  }, { headers: cors });
}

function jwks() {
  const jwk = JSON.parse(Deno.env.get("OAUTH_PUBLIC_KEY_JWK")!);
  return Response.json(
    { keys: [{ ...jwk, use: "sig", alg: "RS256" }] },
    { headers: cors }
  );
}

// Redirect to the app's login form, carrying all OAuth params.
// The app renders the login form and POSTs back to /authorize.
async function authorizeGet(url: URL) {
  const p = url.searchParams;
  const client_id = p.get("client_id");
  const redirect_uri = p.get("redirect_uri");
  const code_challenge = p.get("code_challenge");

  if (!client_id || !redirect_uri || !code_challenge) {
    return Response.json({ error: "invalid_request", error_description: "Missing required parameters" }, { status: 400, headers: cors });
  }

  const { data: client } = await db().from("oauth_clients").select("name, redirect_uris").eq("client_id", client_id).single();
  if (!client) return Response.json({ error: "invalid_client" }, { status: 401, headers: cors });
  if (!client.redirect_uris.includes(redirect_uri)) {
    return Response.json({ error: "invalid_redirect_uri", detail: redirect_uri }, { status: 400, headers: cors });
  }

  const dest = new URL(redirect_uri);
  for (const [k, v] of p.entries()) dest.searchParams.set(k, v);
  dest.searchParams.set("_cc", "login");
  return Response.redirect(dest.toString(), 302);
}

async function authorizePost(req: Request, url: URL) {
  const p = url.searchParams;
  const client_id = p.get("client_id")!;
  const redirect_uri = p.get("redirect_uri")!;
  const state = p.get("state") ?? "";
  const code_challenge = p.get("code_challenge")!;
  const code_challenge_method = p.get("code_challenge_method") ?? "S256";

  const form = await req.formData();
  const email = (form.get("email") as string)?.trim();
  const password = form.get("password") as string;

  function loginError(msg: string) {
    const dest = new URL(redirect_uri);
    for (const [k, v] of p.entries()) dest.searchParams.set(k, v);
    dest.searchParams.set("_cc", "login");
    dest.searchParams.set("_cc_error", msg);
    return Response.redirect(dest.toString(), 302);
  }

  const userClient = createClient(SUPABASE_URL, ANON_KEY, {
    auth: { persistSession: false },
  });
  const { data, error } = await userClient.auth.signInWithPassword({ email, password });

  if (error || !data.user) {
    return loginError("Invalid email or password. Please try again.");
  }

  // Check tenant access stored in app_metadata.allowed_tenants
  const adminClient = createClient(SUPABASE_URL, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false },
  });
  const { data: { user: adminUser } } = await adminClient.auth.admin.getUserById(data.user.id);
  const allowedTenants = adminUser?.app_metadata?.allowed_tenants as string[] | undefined;
  if (allowedTenants && !allowedTenants.includes(client_id)) {
    return loginError(`This account does not have access to ${client_id}.`);
  }

  const code = crypto.randomUUID().replace(/-/g, "");
  const expires_at = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  await db().from("auth_codes").insert({
    code, client_id,
    user_id: data.user.id,
    user_email: data.user.email!,
    redirect_uri, code_challenge, code_challenge_method,
    expires_at,
  });

  const dest = new URL(redirect_uri);
  dest.searchParams.set("code", code);
  if (state) dest.searchParams.set("state", state);
  return Response.redirect(dest.toString(), 302);
}

async function token(req: Request) {
  const ct = req.headers.get("content-type") ?? "";
  let body: URLSearchParams;
  if (ct.includes("application/json")) {
    body = new URLSearchParams(Object.entries(await req.json()).map(([k, v]) => [k, String(v)]));
  } else {
    body = new URLSearchParams(await req.text());
  }

  const grant_type = body.get("grant_type");
  const code = body.get("code");
  const redirect_uri = body.get("redirect_uri");
  const client_id = body.get("client_id");
  const code_verifier = body.get("code_verifier");

  if (grant_type !== "authorization_code" || !code || !client_id) {
    return Response.json({ error: "invalid_request" }, { status: 400, headers: cors });
  }

  const supabase = db();
  const { data: row } = await supabase
    .from("auth_codes")
    .select("*")
    .eq("code", code)
    .eq("client_id", client_id)
    .eq("used", false)
    .gt("expires_at", new Date().toISOString())
    .single();

  if (!row) return Response.json({ error: "invalid_grant", error_description: "Code invalid or expired" }, { status: 400, headers: cors });
  if (row.redirect_uri !== redirect_uri) return Response.json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, { status: 400, headers: cors });

  if (code_verifier && row.code_challenge) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(code_verifier));
    const computed = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    if (computed !== row.code_challenge) {
      return Response.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, { status: 400, headers: cors });
    }
  }

  await supabase.from("auth_codes").update({ used: true }).eq("code", code);

  const key = await getPrivKey();
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    sub: row.user_id,
    email: row.user_email,
    email_verified: true,
    iss: ISSUER,
    aud: client_id,
    iat: now,
    exp: now + 3600,
  };

  const [access_token, id_token] = await Promise.all([
    new SignJWT({ ...claims }).setProtectedHeader({ alg: "RS256", kid: "cc-key-1" }).sign(key),
    new SignJWT({ ...claims }).setProtectedHeader({ alg: "RS256", kid: "cc-key-1" }).sign(key),
  ]);

  return Response.json({
    access_token, id_token,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "openid email profile",
  }, { headers: cors });
}

// Redirect to app signup form with OAuth params in tow.
async function signupGet(url: URL) {
  const p = url.searchParams;
  const redirect_uri = p.get("redirect_uri");
  if (!redirect_uri) return Response.json({ error: "invalid_request" }, { status: 400, headers: cors });

  const dest = new URL(redirect_uri);
  for (const [k, v] of p.entries()) dest.searchParams.set(k, v);
  dest.searchParams.set("_cc", "signup");
  return Response.redirect(dest.toString(), 302);
}

async function signupPost(req: Request, url: URL) {
  const p = url.searchParams;
  const client_id = p.get("client_id")!;
  const redirect_uri = p.get("redirect_uri")!;
  const state = p.get("state") ?? "";
  const code_challenge = p.get("code_challenge")!;
  const code_challenge_method = p.get("code_challenge_method") ?? "S256";

  const form = await req.formData();
  const email = (form.get("email") as string)?.trim();
  const password = form.get("password") as string;

  function signupError(msg: string) {
    const dest = new URL(redirect_uri);
    for (const [k, v] of p.entries()) dest.searchParams.set(k, v);
    dest.searchParams.set("_cc", "signup");
    dest.searchParams.set("_cc_error", msg);
    return Response.redirect(dest.toString(), 302);
  }

  const adminClient = createClient(SUPABASE_URL, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false },
  });
  const { error: createError } = await adminClient.auth.admin.createUser({
    email, password, email_confirm: true,
  });
  if (createError) {
    return signupError(createError.message);
  }

  const userClient = createClient(SUPABASE_URL, ANON_KEY, {
    auth: { persistSession: false },
  });
  const { data } = await userClient.auth.signInWithPassword({ email, password });
  if (!data?.user) {
    const dest = new URL(redirect_uri);
    for (const [k, v] of p.entries()) dest.searchParams.set(k, v);
    dest.searchParams.set("_cc", "login");
    return Response.redirect(dest.toString(), 302);
  }

  const code = crypto.randomUUID().replace(/-/g, "");
  await db().from("auth_codes").insert({
    code, client_id,
    user_id: data.user.id,
    user_email: data.user.email!,
    redirect_uri, code_challenge, code_challenge_method,
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  });

  const dest = new URL(redirect_uri);
  dest.searchParams.set("code", code);
  if (state) dest.searchParams.set("state", state);
  return Response.redirect(dest.toString(), 302);
}

async function userinfo(req: Request) {
  const auth = req.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return Response.json({ error: "invalid_token" }, { status: 401, headers: cors });

  try {
    const { payload } = await jwtVerify(auth.slice(7), await getPubKey(), { issuer: ISSUER });
    return Response.json({ sub: payload.sub, email: payload.email, email_verified: payload.email_verified }, { headers: cors });
  } catch {
    return Response.json({ error: "invalid_token" }, { status: 401, headers: cors });
  }
}
