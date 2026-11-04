
const ALLOWED_HOSTNAMES = new Set([
  "bluechipcreations.com",
  "www.bluechipcreations.com",
]);

const EMAIL_ENDPOINT =
  "https://formsubmit.co/ajax/rehan@bluechipcreations.com";

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

  if (!env.TURNSTILE_SECRET) {
    console.error("TURNSTILE_SECRET is missing.");

    return jsonResponse(
      {
        ok: false,
        error: "Server security configuration is missing",
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
    console.error(
      "Turnstile request failed:",
      String(err)
    );

    return jsonResponse(
      {
        ok: false,
        error: "Security verification is temporarily unavailable",
      },
      502
    );
  }

  // Require successful verification and the expected hostname/action.
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
    // Send email only after Turnstile succeeds.
 
// Send email only after Turnstile succeeds.

const requestId = crypto.randomUUID();

console.log(`[CONTACT ${requestId}] Starting email submission`);

const emailPayload = {
  name: name,
  email: email,
  message: message,
  _subject: "New message from bluechipcreations.com",
  _template: "table",
};

try {
  console.log(`[CONTACT ${requestId}] Sending request to FormSubmit`);

  const emailResponse = await fetch(EMAIL_ENDPOINT, {
    method: "POST",
    headers: {
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
      `[CONTACT ${requestId}] FormSubmit returned invalid JSON`
    );
  }

  // Log the actual response from FormSubmit.
  console.log(
    `[CONTACT ${requestId}] FORMSUBMIT DIAGNOSTIC`,
    JSON.stringify({
      httpStatus: emailResponse.status,
      httpOk: emailResponse.ok,
      contentType: emailResponse.headers.get("content-type"),
      responseBody: responseText.slice(0, 1500),
    })
  );

  const successValue = emailResult?.success;

  const accepted =
    successValue === true ||
    String(successValue).toLowerCase() === "true" ||
    String(successValue) === "1";

  if (!emailResponse.ok || !accepted) {
    console.error(
      `[CONTACT ${requestId}] EMAIL SUBMISSION FAILED`,
      JSON.stringify({
        status: emailResponse.status,
        success: successValue,
        response: emailResult ?? responseText.slice(0, 1500),
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

  console.log(`[CONTACT ${requestId}] EMAIL SENT SUCCESSFULLY`);

  return jsonResponse({
    ok: true,
    requestId: requestId,
  });

} catch (err) {

  console.error(
    `[CONTACT ${requestId}] EMAIL REQUEST EXCEPTION`,
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
