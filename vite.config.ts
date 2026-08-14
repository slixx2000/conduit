import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The frontend lives in `ui/`, but the Tauri CLI must run from the repo root (it
// discovers `src-tauri/tauri.conf.json` by searching subfolders of the cwd). So the
// config sits at the root and points Vite at `ui/`; `build.outDir` is relative to
// `root`, which puts the bundle in `ui/dist` — the path `frontendDist` expects.
export default defineConfig({
  root: "ui",
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: {
    // Tauri drives this dev server via `beforeDevCommand` and connects to `devUrl`, so
    // the port is fixed and failing loudly on a clash beats silently moving.
    port: 5173,
    strictPort: true,
    watch: {
      // Rust rebuilds are Cargo's job; watching them here just churns the dev server.
      ignored: ["**/src-tauri/**", "**/target/**"],
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Matches the WebView2 / WKWebView / webkit2gtk baseline Tauri v2 targets.
    target: "es2021",
    sourcemap: true,
  },
});
