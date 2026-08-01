import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const LINK_UI_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const REPO_ROOT = dirname(dirname(LINK_UI_ROOT));
export const RECORDINGS_ROOT = join(REPO_ROOT, 'dev-docs', 'link-ui-recordings');
export const FLOW_ID = 'link-approval';
export const FLOW_ROOT = join(RECORDINGS_ROOT, FLOW_ID);
export const VIDEO_NAME = 'flow.webm';
export const POSTER_NAME = 'poster.png';
export const METADATA_NAME = 'recording.json';
export const VIEWPORT = { width: 390, height: 844 };

const SOURCE_ROOTS = [
  join(LINK_UI_ROOT, 'index.html'),
  join(LINK_UI_ROOT, 'package.json'),
  join(LINK_UI_ROOT, 'vite.config.ts'),
  join(LINK_UI_ROOT, 'src'),
  join(LINK_UI_ROOT, 'scripts', 'record-flow.mjs'),
  join(LINK_UI_ROOT, 'scripts', 'recording-lib.mjs'),
  join(REPO_ROOT, 'packages', 'secreq', 'src', 'link', 'canonical-v1.fixture.json'),
];

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function sourceFiles(path) {
  if (!statSync(path).isDirectory()) return [path];
  return readdirSync(path, { withFileTypes: true })
    .flatMap((entry) => sourceFiles(join(path, entry.name)))
    .sort();
}

/** Hash every input that can change what the browser recording shows. */
export function sourceSha256() {
  const hash = createHash('sha256');
  const paths = SOURCE_ROOTS.flatMap(sourceFiles).sort();
  for (const path of paths) {
    hash.update(relative(REPO_ROOT, path));
    hash.update('\0');
    hash.update(readFileSync(path));
    hash.update('\0');
  }
  return hash.digest('hex');
}

export function writeMetadata() {
  const metadata = {
    id: FLOW_ID,
    title: 'Approve a request from a linked device',
    caption:
      'Pair the browser, review the exact request details, and sign an approval while the local prompt remains authoritative.',
    width: VIEWPORT.width,
    height: VIEWPORT.height,
    video: VIDEO_NAME,
    poster: POSTER_NAME,
    source_sha256: sourceSha256(),
    video_sha256: sha256File(join(FLOW_ROOT, VIDEO_NAME)),
    poster_sha256: sha256File(join(FLOW_ROOT, POSTER_NAME)),
  };
  writeFileSync(join(FLOW_ROOT, METADATA_NAME), `${JSON.stringify(metadata, null, 2)}\n`);
  return metadata;
}

function pngDimensions(path) {
  const bytes = readFileSync(path);
  if (bytes.length < 24 || bytes.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a') {
    throw new Error(`${relative(REPO_ROOT, path)} is not a PNG`);
  }
  return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
}

function fail(message) {
  throw new Error(`[link-ui recordings] ${message}`);
}

export function checkRecordings() {
  if (!existsSync(RECORDINGS_ROOT)) fail('recording corpus is missing; run pnpm record:flows');

  const fixtureDirs = readdirSync(RECORDINGS_ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  if (fixtureDirs.length !== 1 || fixtureDirs[0] !== FLOW_ID) {
    fail(`expected only the ${FLOW_ID} fixture, found: ${fixtureDirs.join(', ') || 'none'}`);
  }

  const expected = [METADATA_NAME, POSTER_NAME, VIDEO_NAME];
  const actual = readdirSync(FLOW_ROOT).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected.sort())) {
    fail(`${FLOW_ID} must contain exactly ${expected.join(', ')}; found ${actual.join(', ')}`);
  }

  let metadata;
  try {
    metadata = JSON.parse(readFileSync(join(FLOW_ROOT, METADATA_NAME), 'utf8'));
  } catch (error) {
    fail(`could not read ${FLOW_ID}/${METADATA_NAME}: ${error.message}`);
  }

  for (const [key, expectedValue] of Object.entries({
    id: FLOW_ID,
    width: VIEWPORT.width,
    height: VIEWPORT.height,
    video: VIDEO_NAME,
    poster: POSTER_NAME,
  })) {
    if (metadata[key] !== expectedValue) {
      fail(
        `${FLOW_ID}/${METADATA_NAME} has ${key}=${JSON.stringify(metadata[key])}; expected ${JSON.stringify(expectedValue)}`,
      );
    }
  }
  if (typeof metadata.title !== 'string' || typeof metadata.caption !== 'string') {
    fail(`${FLOW_ID}/${METADATA_NAME} needs a title and caption`);
  }

  const videoPath = join(FLOW_ROOT, VIDEO_NAME);
  const posterPath = join(FLOW_ROOT, POSTER_NAME);
  const webmHeader = readFileSync(videoPath).subarray(0, 4).toString('hex');
  if (webmHeader !== '1a45dfa3') fail(`${FLOW_ID}/${VIDEO_NAME} is not a WebM file`);

  const dimensions = pngDimensions(posterPath);
  if (dimensions.width !== VIEWPORT.width || dimensions.height !== VIEWPORT.height) {
    fail(
      `${FLOW_ID}/${POSTER_NAME} is ${dimensions.width}x${dimensions.height}; expected ${VIEWPORT.width}x${VIEWPORT.height}`,
    );
  }

  const checks = [
    ['source_sha256', sourceSha256()],
    ['video_sha256', sha256File(videoPath)],
    ['poster_sha256', sha256File(posterPath)],
  ];
  for (const [field, expectedHash] of checks) {
    if (metadata[field] !== expectedHash) {
      const action =
        field === 'source_sha256'
          ? 'regenerate with pnpm record:flows'
          : 'do not edit generated assets by hand';
      fail(`${FLOW_ID} has a stale ${field}; ${action}`);
    }
  }
}
