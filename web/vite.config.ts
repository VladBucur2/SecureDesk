import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build is static files for Nginx: no inline scripts or styles, so the strict
// Content-Security-Policy of the DMZ proxy (script-src 'self') holds. In development the API
// is proxied, so the browser still sees one origin and the SameSite=Strict cookie works.
export default defineConfig({
  plugins: [react()],
  build: {
    sourcemap: false,
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8080", changeOrigin: false },
    },
  },
});
