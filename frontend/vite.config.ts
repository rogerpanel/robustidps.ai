import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
  build: {
    // Target modern browsers for smaller output
    target: 'es2020',
    // Enable CSS code splitting
    cssCodeSplit: true,
    // Increase chunk size warning (recharts is large)
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        // Manual chunk splitting for optimal caching
        manualChunks: {
          // Core React — changes rarely, cached long-term
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          // Charting library — large but stable
          'vendor-recharts': ['recharts'],
          // NOTE: html2canvas + jspdf are dynamically imported in
          // exportUtils.ts and ExportMenu.tsx — Vite auto-splits them
          // into async chunks that load only when export is triggered.
        },
      },
    },
    // Minification
    minify: 'esbuild',
    // Source maps off in production for smaller deploy
    sourcemap: false,
  },
})
