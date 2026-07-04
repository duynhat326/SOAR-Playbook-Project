const http = require("http");
const fs = require("fs");
const path = require("path");

const HOST = process.env.PLAYWRIGHT_HOST || "127.0.0.1";
const PORT = Number(process.env.PLAYWRIGHT_PORT || "4174");
const ROOT = path.resolve(__dirname, "..", "dist");

const CONTENT_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
};

function resolveAssetPath(urlPath) {
  const requested = decodeURIComponent(urlPath.split("?")[0] || "/");
  const relative = requested === "/" ? "index.html" : requested.replace(/^\/+/, "");
  const fullPath = path.resolve(ROOT, relative);
  if (!fullPath.startsWith(ROOT)) {
    return null;
  }
  return fullPath;
}

const server = http.createServer((request, response) => {
  const target = resolveAssetPath(request.url || "/");
  if (!target) {
    response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Forbidden");
    return;
  }

  fs.readFile(target, (error, body) => {
    if (error) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found");
      return;
    }

    response.writeHead(200, {
      "Content-Type": CONTENT_TYPES[path.extname(target)] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    if (request.method === "HEAD") {
      response.end();
      return;
    }
    response.end(body);
  });
});

let shuttingDown = false;

function shutdown(code) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  server.close(() => {
    process.exit(code);
  });
  setTimeout(() => process.exit(code), 1000).unref();
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

server.listen(PORT, HOST, () => {
  process.stdout.write(`Static server listening on http://${HOST}:${PORT}\n`);
});
