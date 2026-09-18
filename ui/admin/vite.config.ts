import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

// Built assets are embedded into the gateway binary from internal/admin/ui/dist
// and served under /admin/ on the admin listener only.
export default defineConfig({
  plugins: [preact()],
  base: "/admin/",
  build: { outDir: "../../internal/admin/ui/dist", emptyOutDir: true },
  server: {
    port: 5173,
    proxy: { "/admin/api": "http://127.0.0.1:24680" },
  },
});
