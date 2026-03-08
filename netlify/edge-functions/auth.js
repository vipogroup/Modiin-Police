const unauthorized = () => {
  return new Response("Unauthorized", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Evidence Portal"',
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
};

export default async (request, context) => {
  const user = Deno.env.get("BASIC_AUTH_USER");
  const pass = Deno.env.get("BASIC_AUTH_PASS");

  if (!user || !pass) {
    return new Response("Server auth not configured", {
      status: 500,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "text/plain; charset=utf-8",
      },
    });
  }

  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Basic ")) {
    return unauthorized();
  }

  let decoded = "";
  try {
    decoded = atob(header.slice("Basic ".length));
  } catch {
    return unauthorized();
  }

  const colonIndex = decoded.indexOf(":");
  const u = colonIndex >= 0 ? decoded.slice(0, colonIndex) : "";
  const p = colonIndex >= 0 ? decoded.slice(colonIndex + 1) : "";

  if (u !== user || p !== pass) {
    return unauthorized();
  }

  return context.next();
};
