import { copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import vike from 'vike/plugin';
import { defineConfig, type Plugin } from 'vite';

/**
 * Copy the repo-root `docs/*.schema.json` files into `public/schemas/` at the
 * start of every dev/build run, so they are served as stable static URLs
 * (`/schemas/wraps.schema.json`) an editor's `$schema` can point at. The files
 * are owned by other tickets; we only READ them. `public/schemas/` is a build
 * artifact and is gitignored — nothing is duplicated in source control.
 */
function copySchemas(): Plugin {
  return {
    name: 'secreq-copy-schemas',
    buildStart() {
      const src = join(process.cwd(), '..', 'docs');
      const dest = join(process.cwd(), 'public', 'schemas');
      mkdirSync(dest, { recursive: true });
      for (const file of ['wraps.schema.json', 'auto-rules.schema.json']) {
        try {
          copyFileSync(join(src, file), join(dest, file));
        } catch {
          console.warn(`[docs-site] Could not copy schema ${file}`);
        }
      }
    },
  };
}

export default defineConfig({
  base: process.env.BASE_URL || '/',
  plugins: [copySchemas(), vike(), react(), tailwindcss()],
  build: {
    rollupOptions: {
      external: ['/pagefind/pagefind.js'],
    },
  },
  ssr: {
    external: ['gray-matter', 'shiki'],
  },
});
