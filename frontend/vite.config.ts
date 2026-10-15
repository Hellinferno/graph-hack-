import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // REST + SSE from the FastAPI backend (docs/DESIGN.md §6).
      // 127.0.0.1 rather than localhost: Node may resolve localhost to ::1 while uvicorn listens on IPv4.
      '/api': {
        target: process.env.AEGIS_API_URL ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    // react-force-graph-2d bundles d3-force + canvas rendering; ~1 MB before gzip is expected.
    chunkSizeWarningLimit: 1500,
  },
});
