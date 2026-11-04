
const ALLOWED_HOSTNAMES = new Set([
  "bluechipcreations.com",
  "www.bluechipcreations.com",
]);

const RESEND_ENDPOINT = "https://api.resend.com/emails";

const EMAIL_FROM =
  "Website Enquiries <no-reply@enquiry.bluechipcreations.com>";

const EMAIL_TO = "rehan@bluechipcreations.com";

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

async function handleContact(request, env) {
  if (request.method !== "POST") {
    return jsonResponse(
      { ok: false, error: "Method not allowed" },
      405
    );
  }

  if (!env.TURNSTILE_SECRET || !env.RESEND_API_KEY) {
    console.error("Required server secrets are missing.");

    return jsonResponse(
      {
        ok: false,
        error: "Server configuration is missing",
      },
      500
    );
  }

  let form;

  try {
    form = await request.formData();
  } catch (err) {
    console.error("Form parsing failed:", String(err));

    return jsonResponse(
      { ok: false, error: "Invalid form data" },
      400
    );
  }

  const token = form.get("cf-turnstile-response");

  if (
    typeof token !== "string" ||
    token.length === 0 ||
    token.length > 2048
  ) {
    return jsonResponse(
      {
        ok: false,
        error: "Please complete the security check",
      },
      400
    );
  }

  // Honeypot spam protection.
  if (String(form.get("_honey") || "").trim() !== "") {
    return jsonResponse(
      { ok: false, error: "Invalid submission" },
      400
    );
  }

  const name = String(form.get("name") || "").trim();
  const email = String(form.get("email") || "").trim();
  const message = String(form.get("message") || "").trim();

  if (
    !name ||
    name.length > 200 ||
    !email ||
    email.length > 320 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    !message ||
    message.length > 10000
  ) {
    return jsonResponse(
      {
        ok: false,
        error: "Please check the form fields and try again",
      },
      400
    );
  }

  // Verify Turnstile with Cloudflare's server-side API.
  let verification;

  try {
    const verifyBody = new URLSearchParams({
      secret: env.TURNSTILE_SECRET,
      response: token,
    });

    const ip = request.headers.get("CF-Connecting-IP");

    if (ip) {
      verifyBody.set("remoteip", ip);
    }

    const verifyResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: verifyBody,
      }
    );

    if (!verifyResponse.ok) {
      console.error(
        "Turnstile HTTP status:",
        verifyResponse.status
      );

      return jsonResponse(
        {
          ok: false,
          error: "Security verification is temporarily unavailable",
        },
        502
      );
    }

    verification = await verifyResponse.json();
  } catch (err) {
    console.error("Turnstile request failed:", String(err));

    return jsonResponse(
      {
        ok: false,
        error: "Security verification is temporarily unavailable",
      },
      502
    );
  }

  // Require successful verification and expected hostname/action.
  if (
    verification.success !== true ||
    verification.action !== "contact" ||
    !ALLOWED_HOSTNAMES.has(verification.hostname)
  ) {
    console.error(
      "Turnstile verification rejected:",
      JSON.stringify({
        success: verification.success,
        action: verification.action,
        hostname: verification.hostname,
        errorCodes: verification["error-codes"],
      })
    );

    return jsonResponse(
      {
        ok: false,
        error: "Security check failed. Please try again.",
      },
      403
    );
  }

  // Send email only after Turnstile succeeds.
  const requestId = crypto.randomUUID();

  console.log(`[CONTACT ${requestId}] Starting Resend submission`);

  const emailPayload = {
    from: EMAIL_FROM,
    to: [EMAIL_TO],
    reply_to: email,
    subject: "New Website Enquiry - Bluechip Creations",

    text: `You have received a new enquiry through your website.

Name: ${name}
Email: ${email}

Message:
${message}

--------------------------------
Bluechip Creations Website Contact Form`,
  };

  try {
    console.log(`[CONTACT ${requestId}] Sending email through Resend`);

    const emailResponse = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
        "Accept": "application/json",
      },
      body: JSON.stringify(emailPayload),
    });

    const responseText = await emailResponse.text();

    let emailResult = null;

    try {
      emailResult = JSON.parse(responseText);
    } catch {
      console.error(
        `[CONTACT ${requestId}] Resend returned invalid JSON`
      );
    }

    // Diagnostic logging without exposing visitor information.
    console.log(
      `[CONTACT ${requestId}] RESEND DIAGNOSTIC`,
      JSON.stringify({
        httpStatus: emailResponse.status,
        httpOk: emailResponse.ok,
        resendId: emailResult?.id || null,
        error: emailResult?.message || emailResult?.error || null,
      })
    );

    if (!emailResponse.ok || !emailResult?.id) {
      console.error(
        `[CONTACT ${requestId}] EMAIL SUBMISSION FAILED`,
        JSON.stringify({
          status: emailResponse.status,
          error: emailResult?.message || emailResult?.error || "Unknown Resend error",
          details: emailResult?.name || null,
        })
      );

      return jsonResponse(
        {
          ok: false,
          error: "Unable to send your message right now",
          requestId: requestId,
        },
        502
      );
    }

    console.log(
      `[CONTACT ${requestId}] EMAIL ACCEPTED BY RESEND`,
      emailResult.id
    );

    return jsonResponse({
      ok: true,
      requestId: requestId,
    });

  } catch (err) {
    console.error(
      `[CONTACT ${requestId}] RESEND REQUEST EXCEPTION`,
      JSON.stringify({
        message: String(err),
        name: err?.name,
      })
    );

    return jsonResponse(
      {
        ok: false,
        error: "Unable to reach the email service",
        requestId: requestId,
      },
      502
    );
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/contact") {
      return handleContact(request, env);
    }

    // Serve the static website through the ASSETS binding.
    return env.ASSETS.fetch(request);
  },
};
