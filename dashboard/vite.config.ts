import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, "..", "");
  const proxyTarget = (env.SOAR_API_PROXY_TARGET || env.VITE_SOAR_API_BASE_URL || "http://127.0.0.1:8000")
    .trim()
    .replace(/\/$/, "");

  return {
    envDir: "..",
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/soar-api": {
          target: proxyTarget,
          changeOrigin: true,
          rewrite: (requestPath) => requestPath.replace(/^\/soar-api/, ""),
        },
      },
    },
  };
});
