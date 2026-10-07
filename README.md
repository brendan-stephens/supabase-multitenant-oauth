# supabase-multitenant-oauth

A multi-tenant OAuth 2.1 + PKCE demo built entirely on [Supabase Edge Functions](https://supabase.com/docs/guides/functions). No third-party auth service — a custom OIDC provider runs as a single Edge Function and issues RS256-signed JWTs that tenant APIs verify independently.

**[Live demo](https://brendan-stephens.github.io/supabase-multitenant-oauth/demo) · [Explainer](https://brendan-stephens.github.io/supabase-multitenant-oauth)**

---

## How it works

Three isolated Supabase projects:

| Project | Role | What it does |
|---|---|---|
| **Command Center** | OIDC Provider | Issues auth codes, exchanges them for RS256 JWTs, exposes JWKS |
| **Tenant Alpha** | Resource Server | Verifies JWTs via CC's JWKS, serves per-user notes |
| **Tenant Beta** | Resource Server | Same pattern, separate data store |

The demo app runs in the browser. It implements the full OAuth 2.1 Authorization Code + PKCE flow — no server-side component needed for the client.

### Authorization flow

```
App ──── GET /authorize (code_challenge) ──────► Command Center
App ◄─── 302 → app?_cc=login ──────────────────  Command Center
App ──── POST /authorize (email, password) ────► Command Center
App ◄─── 302 → app?code=xyz ───────────────────  Command Center
App ──── POST /token (code + code_verifier) ───► Command Center
App ◄─── { access_token, id_token } (RS256 JWT)  Command Center
App ──── GET /data  Bearer <JWT> ───────────────────────────────► Tenant
         Tenant ── GET /jwks ──────────────────► Command Center
         Tenant ◄─ { keys } ──────────────────── Command Center
App ◄──────────────── { notes } (scoped to JWT sub) ────────────  Tenant
```

### Key design decisions

- **No HTML from Edge Functions** — `GET /authorize` redirects back to the app with `?_cc=login`, letting the app render forms natively. This avoids Cloudflare forcing `text/plain` on function responses.
- **PKCE (S256)** — the `code_verifier` never leaves the client; the server only sees the `SHA-256` hash during `/authorize` and verifies the raw value at `/token`.
- **Per-tenant access** — stored in `app_metadata.allowed_tenants` on the CC user record. Tenants have no user table — they trust the JWT `sub` as `user_id`.
- **RLS isolation** — each tenant's `tenant_notes` table has an RLS policy enforcing `user_id = auth.uid()`, scoping rows to the authenticated JWT subject.

---

## Why not use Supabase's built-in OAuth Server?

Supabase has an **OAuth Server** setting (under Authentication → Configuration) that lets a Supabase project act as an OAuth provider — essentially "Sign in with Supabase." That feature is designed for a different use case: letting *external* applications delegate authentication to your Supabase project, similar to "Sign in with Google."

This project solves a different problem: **one identity provider controlling access to multiple separate Supabase projects**, where each project is a fully isolated tenant with its own database. The built-in OAuth Server can't federate identity across multiple Supabase projects out of the box — it issues tokens for its own project's auth system, not for other projects to consume.

By building the OIDC provider as an Edge Function we get:

- **Cross-project JWT trust** — tenant functions verify the CC's RS256 signature via JWKS; they don't need to share a database or a Supabase org
- **Per-tenant access control** — `app_metadata.allowed_tenants` on the CC user record gates which tenants a user can reach, all enforced server-side before an auth code is issued
- **Full OIDC spec compliance** — discovery document, JWKS endpoint, authorization code flow, PKCE, userinfo endpoint — any standard OAuth 2.1 client can integrate with it
- **No dependency on Supabase's auth roadmap** — the provider logic lives in code you own and deploy

The tradeoff is complexity: you own the token issuance, key rotation, and auth code TTL logic. The built-in OAuth Server is the right default if you just need to let a single external app authenticate against one Supabase project.

---

## Project structure

```
command-center/supabase/functions/oidc/   OIDC provider Edge Function
tenant-alpha/supabase/functions/data/    Tenant Alpha data API
tenant-beta/supabase/functions/data/     Tenant Beta data API
tenant-app/index.html                    Demo app (single HTML file)
docs/                                    GitHub Pages explainer + live demo
```

---

## Setup

### Prerequisites

- [Supabase CLI](https://supabase.com/docs/guides/cli) (`npm i -g supabase`)
- Three Supabase projects (free tier works): Command Center, Tenant Alpha, Tenant Beta
- `openssl` for key generation

### 1 — Generate an RS256 key pair

```bash
# Private key (PEM)
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# Public key as JWK (pipe through node or use a tool like https://jwkset.com)
openssl rsa -in private.pem -pubout -outform PEM -out public.pem
```

Convert the public key to JWK format — you need a JSON object with `kty`, `n`, `e` fields. A quick way:

```js
// node
const { createPublicKey } = require('crypto');
const fs = require('fs');
const key = createPublicKey(fs.readFileSync('public.pem'));
console.log(JSON.stringify(key.export({ format: 'jwk' })));
```

Keep both values — you'll use them as Edge Function secrets.

### 2 — Create tables in Command Center

Run in the Command Center project's SQL editor:

```sql
-- OAuth clients
CREATE TABLE oauth_clients (
  client_id    TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  redirect_uris TEXT[] NOT NULL DEFAULT '{}'
);

-- Authorization codes (short-lived, single-use)
CREATE TABLE auth_codes (
  code                  TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  user_id               UUID NOT NULL,
  user_email            TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  expires_at            TIMESTAMPTZ NOT NULL,
  used                  BOOLEAN NOT NULL DEFAULT FALSE
);

-- Register your tenant clients
INSERT INTO oauth_clients (client_id, name, redirect_uris) VALUES
  ('tenant-alpha', 'Tenant Alpha', ARRAY['http://localhost:3000', 'http://localhost:5173']),
  ('tenant-beta',  'Tenant Beta',  ARRAY['http://localhost:3000', 'http://localhost:5173']);
```

Add any additional redirect URIs your app will be served from.

### 3 — Create tables in each Tenant project

Run in both Tenant Alpha and Tenant Beta SQL editors:

```sql
CREATE TABLE tenant_notes (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL,
  content    TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE tenant_notes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "own rows"
  ON tenant_notes FOR ALL
  TO authenticated
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());
```

### 4 — Deploy Edge Functions

```bash
# Command Center OIDC provider
supabase functions deploy oidc --project-ref <CC_PROJECT_REF>

# Tenant Alpha data API
supabase functions deploy data --project-ref <ALPHA_PROJECT_REF>

# Tenant Beta data API
supabase functions deploy data --project-ref <BETA_PROJECT_REF>
```

### 5 — Set secrets

**Command Center:**

```bash
supabase secrets set \
  OAUTH_PRIVATE_KEY="$(cat private.pem)" \
  OAUTH_PUBLIC_KEY_JWK='{"kty":"RSA","n":"...","e":"AQAB"}' \
  --project-ref <CC_PROJECT_REF>
```

`SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` are injected automatically by the Edge Runtime — no need to set them manually.

**Tenant Alpha and Beta:** No additional secrets needed beyond the auto-injected ones. The JWKS URL is hardcoded in each function to point at the Command Center.

> If you're using your own CC project ref, update `CC_ISSUER` at the top of each tenant function before deploying.

### 6 — Create demo users (optional)

Create users via the Supabase dashboard (Authentication → Users → Add user) or the admin API. To restrict a user to specific tenants, set their `app_metadata`:

```json
{ "allowed_tenants": ["tenant-alpha"] }
```

A user without `allowed_tenants` in their metadata can access any tenant. Set it to an array to restrict access.

---

## Adding a new tenant

Because the Command Center exposes a standard OIDC discovery document at `/.well-known/openid-configuration`, new tenants self-configure — there's no key exchange or shared secret between the tenant and the CC.

### 1 — Deploy the tenant function

Copy either existing tenant function, update the two constants at the top, and deploy to a new Supabase project:

```ts
// tenant-gamma/supabase/functions/data/index.ts
const CC_ISSUER = "https://<CC_PROJECT_REF>.supabase.co/functions/v1/oidc";
const JWKS      = createRemoteJWKSet(new URL(`${CC_ISSUER}/jwks`));
const TENANT_ID = "tenant-gamma";
```

```bash
supabase functions deploy data --project-ref <GAMMA_PROJECT_REF>
```

Don't forget to create the `tenant_notes` table and RLS policy in the new project (see [step 3](#3--create-tables-in-each-tenant-project) in Setup).

### 2 — Register the client in Command Center

One row in `oauth_clients` — the OIDC function reads it live, no redeploy needed:

```sql
INSERT INTO oauth_clients (client_id, name, redirect_uris)
VALUES (
  'tenant-gamma',
  'Tenant Gamma',
  ARRAY['https://your-app.com']
);
```

### 3 — Grant users access

Add `tenant-gamma` to the user's `app_metadata.allowed_tenants` array in the CC project:

```sql
UPDATE auth.users
SET raw_app_meta_data = raw_app_meta_data || '{"allowed_tenants":["tenant-gamma"]}'::jsonb
WHERE email = 'user@example.com';
```

Users without an `allowed_tenants` array in their metadata can access any tenant. Set it to restrict.

---

## Running the demo app locally

The demo app is a single HTML file — no build step.

```bash
# Any static file server works; these ports are pre-registered as redirect URIs
npx serve tenant-app -l 3000
# or
python3 -m http.server 3000 -d tenant-app
```

Then open `http://localhost:3000`.

To add more redirect URIs, update the `redirect_uris` column in `oauth_clients`:

```sql
UPDATE oauth_clients
SET redirect_uris = redirect_uris || ARRAY['http://localhost:YOUR_PORT']
WHERE client_id IN ('tenant-alpha', 'tenant-beta');
```

---

## Live demo

The `docs/demo/` directory is a copy of the demo app deployed to GitHub Pages. It's wired to the same Supabase projects as the local demo. You can sign in with:

| Email | Password | Access |
|---|---|---|
| `alpha@demo.local` | `Demo1234!` | Tenant Alpha only |
| `beta@demo.local` | `Demo1234!` | Tenant Beta only |
| `both@demo.local` | `Demo1234!` | Alpha + Beta |

---

## Tech stack

- **[Supabase Edge Functions](https://supabase.com/docs/guides/functions)** — Deno-based serverless functions for both the OIDC provider and tenant APIs
- **[jose](https://github.com/panva/jose)** (`npm:jose@5`) — RS256 JWT signing and remote JWKS verification
- **[supabase-js](https://github.com/supabase/supabase-js)** (`jsr:@supabase/supabase-js@2`) — auth and database access within Edge Functions
- **Vanilla JS** — demo app has no build step or dependencies
