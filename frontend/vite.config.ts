import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { tsconfigPaths: true },
  server: {
    // `npm run dev` serves the app on Vite's port and forwards API calls to the
    // Express server in the repo root (npm start), so both can run side by side.
    proxy: { "/api": "http://127.0.0.1:3000" },
  },
  build: { outDir: "dist" },
});
