import rehypeShiki from '@shikijs/rehype';
import { join } from 'node:path';
import type { Config } from 'vike/types';

/**
 * Config for `vike-plugin-typedoc`. It reads the TypeDoc JSON emitted by the
 * `typedoc` build step (see package.json `build`/`extract-docs` scripts and
 * `typedoc.json`) from `typedocDir`, and resolves each package's npm name from
 * `<packagesDir>/<slug>/package.json`.
 *
 * Only ONE package is documented here: `secreq-rule` (the AssemblyScript SDK).
 * The Rust crate at `packages/secreq` is deliberately not a TypeDoc entry.
 *
 * `process.cwd()` is the `docs-site/` dir during both `vike dev` and
 * `vike build` (same assumption the docs loader makes in
 * `+onCreateGlobalContext.server.ts`).
 *
 * `theme` highlights rendered signatures; `rehypePlugins` highlights fenced
 * code inside doc-comment prose — both use `github-dark` to match the rest of
 * the site's markdown pipeline (`server/utils/markdown.ts`).
 */
const root = process.cwd();

export default {
  typedocDir: join(root, '.typedoc'),
  packagesDir: join(root, '..', 'packages'),
  theme: 'github-dark',
  rehypePlugins: [[rehypeShiki, { theme: 'github-dark' }]],
} satisfies Config['typedoc'];
