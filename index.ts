import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (request: Request) => {
  if (request.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) {
    return jsonResponse({ error: "Authentication required" }, 401);
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const publishableKey = Deno.env.get("SUPABASE_PUBLISHABLE_KEY");
  const secretKey = Deno.env.get("SUPABASE_SECRET_KEY");
  if (!supabaseUrl || !publishableKey || !secretKey) {
    console.error("Missing Supabase function secrets");
    return jsonResponse({ error: "Server configuration error" }, 500);
  }

  const userClient = createClient(supabaseUrl, publishableKey, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: userData, error: userError } = await userClient.auth.getUser();
  if (userError || !userData.user) return jsonResponse({ error: "Invalid or expired session" }, 401);

  let body: { content_id?: string };
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Request body must be valid JSON" }, 400);
  }

  const contentId = body.content_id;
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!contentId || !uuidPattern.test(contentId)) {
    return jsonResponse({ error: "A valid content_id is required" }, 400);
  }

  const adminClient = createClient(supabaseUrl, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // The server reads the current price and currency. Never accept price/currency
  // supplied by the client as the source of truth.
  const { data: content, error: contentError } = await adminClient
    .from("content_items")
    .select("id, title, price_amount, currency_code, status, published_at, expires_at")
    .eq("id", contentId)
    .maybeSingle();

  if (contentError) {
    console.error("Content lookup failed", contentError.message);
    return jsonResponse({ error: "Could not load content" }, 500);
  }
  if (!content || content.status !== "published") {
    return jsonResponse({ error: "Content is not available for purchase" }, 404);
  }

  const now = Date.now();
  if (content.published_at && Date.parse(content.published_at) > now) {
    return jsonResponse({ error: "Content is not published yet" }, 409);
  }
  if (content.expires_at && Date.parse(content.expires_at) <= now) {
    return jsonResponse({ error: "Content has expired" }, 409);
  }

  // Prevent creating duplicate pending/paid orders for content already owned.
  const { data: existingEntitlement, error: entitlementError } = await adminClient
    .from("entitlements")
    .select("id, status, expires_at")
    .eq("user_id", userData.user.id)
    .eq("content_id", contentId)
    .maybeSingle();

  if (entitlementError) {
    console.error("Entitlement lookup failed", entitlementError.message);
    return jsonResponse({ error: "Could not verify existing access" }, 500);
  }

  if (existingEntitlement?.status === "active" &&
      (!existingEntitlement.expires_at || Date.parse(existingEntitlement.expires_at) > now)) {
    return jsonResponse({ error: "You already have access to this content" }, 409);
  }

  const { data: order, error: orderError } = await adminClient
    .from("orders")
    .insert({
      user_id: userData.user.id,
      status: "pending",
      currency_code: content.currency_code,
      subtotal_amount: content.price_amount,
      total_amount: content.price_amount,
    })
    .select("id, order_number, status, currency_code, total_amount, created_at")
    .single();

  if (orderError || !order) {
    console.error("Order creation failed", orderError?.message);
    return jsonResponse({ error: "Could not create order" }, 500);
  }

  const { error: itemError } = await adminClient
    .from("order_items")
    .insert({
      order_id: order.id,
      content_id: content.id,
      title_snapshot: content.title,
      unit_price: content.price_amount,
      currency_code: content.currency_code,
    });

  if (itemError) {
    console.error("Order item creation failed", itemError.message);
    // Best-effort cleanup so an incomplete pending order is not left behind.
    await adminClient.from("orders").delete().eq("id", order.id).eq("status", "pending");
    return jsonResponse({ error: "Could not create order item" }, 500);
  }

  // This function only creates a pending order. It does not collect money,
  // mark an order paid, or grant content access. Those actions require an
  // approved payment provider and a separately verified server-side webhook.
  return jsonResponse({ order });
});
