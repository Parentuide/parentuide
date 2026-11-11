import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigin = "https://parentuide.github.io";

function respond(
  body: Record<string, unknown>,
  status = 200,
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "content-type",
      "Vary": "Origin",
    },
  });
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");

  if (origin !== allowedOrigin) {
    return new Response("Forbidden origin", { status: 403 });
  }

  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": allowedOrigin,
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "content-type",
        "Vary": "Origin",
      },
    });
  }

  if (req.method !== "POST") {
    return respond({ error: "Method not allowed" }, 405);
  }

  try {
    const body = await req.json();

    if (
      !body ||
      typeof body !== "object" ||
      !["parent", "specialist"].includes(body.type) ||
      !body.answers ||
      typeof body.answers !== "object" ||
      Array.isArray(body.answers) ||
      typeof body.turnstileToken !== "string" ||
      body.turnstileToken.length === 0
    ) {
      return respond({ error: "Invalid submission" }, 400);
    }

    if (JSON.stringify(body.answers).length > 10000) {
      return respond({ error: "Submission too large" }, 413);
    }

    const turnstileSecret = Deno.env.get("TURNSTILE_SECRET_KEY");
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!turnstileSecret || !supabaseUrl || !serviceKey) {
      return respond({ error: "Server configuration error" }, 500);
    }

    const verification = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          secret: turnstileSecret,
          response: body.turnstileToken,
        }),
      },
    );

    if (!verification.ok) {
      return respond({ error: "Verification unavailable" }, 503);
    }

    const result = await verification.json();

    if (
      result.success !== true ||
      result.hostname !== "parentuide.github.io"
    ) {
      return respond({ error: "Verification failed" }, 403);
    }

    const supabase = createClient(supabaseUrl, serviceKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });

    const table = body.type === "parent"
      ? "parent_survey_responses"
      : "specialist_survey_responses";

    const { error } = await supabase
      .from(table)
      .insert({ answers: body.answers });

    if (error) {
      return respond({ error: "Could not save submission" }, 500);
    }

    return respond({ success: true });
  } catch {
    return respond({ error: "Invalid request" }, 400);
  }
});
