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
        // Stable, non-hashed names keep the committed bundle's diff readable in
        // review. All three patterns must be pinned: an unpinned chunkFileNames
        // emits a content-hashed filename on the first dynamic import, and that
        // arrives as a NEW untracked file rather than a modified one.
        entryFileNames: 'app.js',
        assetFileNames: 'app-[name].[ext]',
        chunkFileNames: 'app-chunk-[name].js',
      },
    },
  },
})
