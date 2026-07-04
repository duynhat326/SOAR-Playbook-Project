const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-proto",
]);

function resolveProxyTarget() {
  const rawTarget =
    process.env.SOAR_API_PROXY_TARGET ||
    process.env.SOAR_API_BASE_URL ||
    process.env.VITE_SOAR_API_BASE_URL ||
    "";
  const target = rawTarget.trim().replace(/\/$/, "");

  if (!target) {
    throw new Error("SOAR_API_PROXY_TARGET is not configured.");
  }

  return target;
}

function resolveProxyToken() {
  return (process.env.SOAR_API_PROXY_TOKEN || process.env.SOAR_AUTH_TOKEN || "").trim();
}

function copyRequestHeaders(req) {
  const nextHeaders = new Headers();

  Object.entries(req.headers ?? {}).forEach(([key, value]) => {
    if (HOP_BY_HOP_HEADERS.has(key.toLowerCase()) || value == null) {
      return;
    }

    if (Array.isArray(value)) {
      value.forEach((entry) => nextHeaders.append(key, entry));
      return;
    }

    nextHeaders.set(key, String(value));
  });

  return nextHeaders;
}

function buildRequestBody(req) {
  const method = String(req.method || "GET").toUpperCase();
  if (method === "GET" || method === "HEAD") {
    return undefined;
  }

  if (req.body == null) {
    return undefined;
  }

  if (Buffer.isBuffer(req.body) || typeof req.body === "string" || req.body instanceof Uint8Array) {
    return req.body;
  }

  return JSON.stringify(req.body);
}

function forwardResponseHeaders(upstreamResponse, res) {
  upstreamResponse.headers.forEach((value, key) => {
    if (HOP_BY_HOP_HEADERS.has(key.toLowerCase()) || key.toLowerCase() === "content-encoding") {
      return;
    }

    res.setHeader(key, value);
  });
}

export async function proxyRequest(req, res, upstreamPath) {
  try {
    const target = resolveProxyTarget();
    const search = new URL(req.url || "/", "http://localhost").search;
    const upstreamUrl = `${target}${upstreamPath}${search}`;
    const headers = copyRequestHeaders(req);
    const proxyToken = resolveProxyToken();

    if (proxyToken) {
      headers.set("authorization", `Bearer ${proxyToken}`);
    }

    const upstreamResponse = await fetch(upstreamUrl, {
      method: req.method,
      headers,
      body: buildRequestBody(req),
      redirect: "manual",
    });

    res.statusCode = upstreamResponse.status;
    forwardResponseHeaders(upstreamResponse, res);

    const payload = Buffer.from(await upstreamResponse.arrayBuffer());
    res.send(payload);
  } catch (error) {
    res.status(502).json({
      detail: error instanceof Error ? error.message : "Unable to reach the SOAR API upstream.",
    });
  }
}
