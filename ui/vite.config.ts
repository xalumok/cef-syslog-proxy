import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The build output is served by FastAPI as static files. Node.js is a build-time
// dependency only and never runs in production.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: true },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true, ws: true },
    },
  },
});
