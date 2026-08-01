import { copyFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const packageRoot = fileURLToPath(new URL('..', import.meta.url));
const builtDist = fileURLToPath(new URL('../dist/', import.meta.url));
const crateDist = fileURLToPath(new URL('../../secreq/dist/link-ui/', import.meta.url));

// Cargo packages cannot include a sibling workspace directory. Keep the Vite
// output at packages/link-ui/dist for web-tooling freshness checks, then mirror
// the same three committed files inside the crate so `cargo install secreq`
// needs neither this source package nor a Node toolchain.
await mkdir(crateDist, { recursive: true });
for (const filename of ['index.html', 'app.js', 'app.css']) {
  await copyFile(`${builtDist}${filename}`, `${crateDist}${filename}`);
}

console.log(`mirrored link-ui assets from ${packageRoot}dist into the secreq crate`);
