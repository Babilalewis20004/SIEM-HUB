import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Baseline hardening headers -- absence of these is what the ZAP DAST scan
// (.github/workflows/security.yml) flags first. Vite's dev/preview servers
// are the only thing standing in front of the SPA in CI; whatever actually
// hosts the production build (nginx, a CDN, ...) needs the same headers
// configured there too, since this config doesn't apply to it.
const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; " +
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
};

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    headers: securityHeaders,
    proxy: {
      "/api": {
        target: "http://localhost:5000",
        changeOrigin: true,
      },
      "/socket.io": {
        target: "http://localhost:5000",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  // `vite preview` (serves the production build, e.g. for the DAST scan in
  // CI) doesn't fall back to `server.proxy`/`server.headers` -- it needs its
  // own copies or API calls 404 and responses go out unhardened.
  preview: {
    port: 4173,
    // Without this, Vite binds the preview server to "localhost" which can
    // resolve to the IPv6 loopback (::1) only -- unreachable for anything
    // that reaches it as an IPv4 peer (e.g. the ZAP DAST job's container in
    // .github/workflows/security.yml), same class of bind-address bug
    // run.py's HOST var fixes for the backend (see docker-entrypoint notes).
    host: true,
    headers: securityHeaders,
    proxy: {
      "/api": {
        target: "http://localhost:5000",
        changeOrigin: true,
      },
      "/socket.io": {
        target: "http://localhost:5000",
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
