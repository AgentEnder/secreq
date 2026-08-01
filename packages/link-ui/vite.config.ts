import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    assetsDir: '',
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        assetFileNames: 'app.[ext]',
      },
    },
  },
});
