import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { createRemoteJWKSet, jwtVerify } from "npm:jose@5";

const CC_ISSUER = "https://mqawauxnyjkgcfwgahmh.supabase.co/functions/v1/oidc";
const JWKS = createRemoteJWKSet(new URL(`${CC_ISSUER}/jwks`));
const TENANT_ID = "tenant-alpha";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

async function verifyToken(req: Request): Promise<{ sub: string; email: string } | null> {
  const auth = req.headers.get("Authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  try {
    const { payload } = await jwtVerify(auth.slice(7), JWKS, {
      issuer: CC_ISSUER,
      audience: TENANT_ID,
    });
    return { sub: payload.sub!, email: payload.email as string };
  } catch (e) {
    console.error("[auth]", e);
    return null;
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });

  const user = await verifyToken(req);
  if (!user) return Response.json({ error: "unauthorized" }, { status: 401, headers: cors });

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    { auth: { persistSession: false } }
  );

  const url = new URL(req.url);
  const path = url.pathname.replace(/.*\/data/, "") || "/";

  if (req.method === "GET" && (path === "/" || path === "/notes")) {
    const { data, error } = await supabase
      .from("tenant_notes")
      .select("id, content, created_at")
      .eq("user_id", user.sub)
      .order("created_at", { ascending: false });
    if (error) return Response.json({ error: error.message }, { status: 500, headers: cors });
    return Response.json({ user, tenant: TENANT_ID, notes: data }, { headers: cors });
  }

  if (req.method === "POST" && (path === "/" || path === "/notes")) {
    const { content } = await req.json();
    const { data, error } = await supabase
      .from("tenant_notes")
      .insert({ user_id: user.sub, content })
      .select("id, content, created_at")
      .single();
    if (error) return Response.json({ error: error.message }, { status: 500, headers: cors });
    return Response.json(data, { status: 201, headers: cors });
  }

  return Response.json({ error: "not_found" }, { status: 404, headers: cors });
});
