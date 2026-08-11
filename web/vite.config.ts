import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  // The server mounts the UI at '/', but relative paths keep the built
  // index.html working regardless of how it's served.
  base: './',
  build: {
    outDir: '../internal/ui/dist',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // Stable, non-hashed entry names keep the committed bundle's diff
        // readable in review; asset hashing still applies to imported chunks.
        entryFileNames: 'app.js',
        assetFileNames: 'app-[name].[ext]',
      },
    },
  },
})
