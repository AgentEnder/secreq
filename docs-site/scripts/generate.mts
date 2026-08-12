/**
 * Materialise everything the app imports at module load but does not commit:
 * `.generated/{shots,terms,recordings}.json`, and the copies under `public/`
 * that those indexes name.
 *
 * All of it is produced by the `secreq-copy-repo-assets` Vite plugin, whose
 * `buildStart` hook runs under `vike build` and `vike dev` — and nowhere else.
 * Vitest loads `vitest.config.ts`, which carries no plugins, so a checkout that
 * has never been built has nothing for `term-markup.ts`, `shot-markup.ts` and
 * `screen-flow-markup.ts` to import. The suite then fails on module resolution
 * rather than on anything it means to assert:
 *
 *     Failed to resolve import "./.generated/terms.json" from "term-markup.ts"
 *
 * That only ever reproduced in CI, because a developer's tree has almost always
 * been built at least once. `docs-site:test` depends on the `generate` target
 * that runs this, so the inputs exist before Vitest looks for them.
 *
 * This calls the plugin's own hook rather than reimplementing the copy rules,
 * so there is one description of what gets published and where. The cost is
 * that a generate also refreshes `public/` — harmless, since that directory is
 * a gitignored build artifact the site would rewrite anyway.
 *
 * Must run with `docs-site` as the working directory: the plugin resolves the
 * repo root and its output directories relative to `process.cwd()`.
 */
import { copyRepoAssets } from '../vite.config.ts';

const { buildStart } = copyRepoAssets();

if (typeof buildStart !== 'function') {
  throw new Error(
    '[docs-site] secreq-copy-repo-assets no longer exposes buildStart as a function; ' +
      'update scripts/generate.mts to call whatever hook now writes .generated/.',
  );
}

// Declared as a Rollup hook, but it reads no `this` — the plugin resolves
// everything from `process.cwd()` — so invoking it outside a build is sound.
await (buildStart as unknown as () => void | Promise<void>)();
