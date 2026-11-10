import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import compression from 'vite-plugin-compression'

export default defineConfig({
  plugins: [
    react(),
    // Pre-compress assets at build time so nginx serves static .gz/.br
    // files instead of compressing on every request
    compression({ algorithm: 'gzip', ext: '.gz', threshold: 1024 }),
    compression({ algorithm: 'brotliCompress', ext: '.br', threshold: 1024 }),
  ],
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
    // Disable automatic modulepreload injection — the default preloads ALL
    // reachable chunks (including vendor-export at 549KB) which blocks
    // initial paint on slow connections.  Critical vendor-react is preloaded
    // manually in index.html instead.
    modulePreload: false,
    rollupOptions: {
      output: {
        // Manual chunk splitting for optimal caching
        manualChunks: {
          // Core React — changes rarely, cached long-term
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          // Charting library — large but stable
          'vendor-recharts': ['recharts'],
          // Export libs — only loaded when user triggers export
          'vendor-export': ['html2canvas', 'jspdf'],
        },
      },
    },
    // Minification
    minify: 'esbuild',
    // Source maps off in production for smaller deploy
    sourcemap: false,
  },
})
