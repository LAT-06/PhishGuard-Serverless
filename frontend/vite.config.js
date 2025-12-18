import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// Vite configuration for Vue 3 development
// https://vitejs.dev/config/
export default defineConfig({
  // Vue 3 plugin with hot module replacement
  plugins: [vue()],

  // Development server configuration
  server: {
    port: 3000,
    open: true, // Auto-open browser on start

    // Proxy API requests to backend server
    // This avoids CORS issues during development
    proxy: {
      "/api": {
        target: "http://localhost:5000",
        changeOrigin: true,
        secure: false,
        // Optionally log proxy requests
        configure: (proxy, _options) => {
          proxy.on("error", (err, _req, _res) => {
            console.log("proxy error", err);
          });
          proxy.on("proxyReq", (proxyReq, req, _res) => {
            console.log("Proxying:", req.method, req.url, "->", proxyReq.path);
          });
        },
      },
    },
  },

  // Build configuration
  build: {
    outDir: "dist",
    sourcemap: true,
    // Optimize chunk size
    rollupOptions: {
      output: {
        manualChunks: {
          "vue-vendor": ["vue"],
        },
      },
    },
  },
});
