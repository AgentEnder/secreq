import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    // Cargo cannot package a sibling workspace directory. Write the committed
    // bundle directly inside the crate so `cargo install secreq` needs no Node
    // toolchain and there is only one copy to keep fresh.
    outDir: '../secreq/dist/link-ui',
    emptyOutDir: true,
    assetsDir: '',
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        assetFileNames: 'app.[ext]',
      },
    },
  },
});
