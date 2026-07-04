import { proxyRequest } from "../_proxy.js";

export default async function handler(req, res) {
  const segments = Array.isArray(req.query?.path)
    ? req.query.path
    : typeof req.query?.path === "string"
      ? [req.query.path]
      : [];
  const upstreamPath = `/api/v1/${segments.map((segment) => encodeURIComponent(String(segment))).join("/")}`;

  return proxyRequest(req, res, upstreamPath);
}
