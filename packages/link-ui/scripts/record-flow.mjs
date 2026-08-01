#!/usr/bin/env node

import { createPublicKey, verify } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, normalize } from 'node:path';
import { chromium } from 'playwright';

import {
  FLOW_ROOT,
  POSTER_NAME,
  REPO_ROOT,
  VIDEO_NAME,
  VIEWPORT,
  writeMetadata,
} from './recording-lib.mjs';

const DIST = join(REPO_ROOT, 'packages', 'secreq', 'dist', 'link-ui');
const CANONICAL_FIXTURE = join(
  REPO_ROOT,
  'packages',
  'secreq',
  'src',
  'link',
  'canonical-v1.fixture.json',
);
const fixture = JSON.parse(readFileSync(CANONICAL_FIXTURE, 'utf8')).cases[0];
const awaiting = {
  request_id: 'recorded-link-request',
  ask_hash_hex: fixture.sha256,
  representative: fixture.ask,
  status: 'Awaiting',
};
const emptySnapshot = { queue: [] };
const pendingSnapshot = { queue: [awaiting] };
const resolvingSnapshot = {
  queue: [{ ...awaiting, status: 'Resolving', resolving_since: 1_700_000_000_000 }],
};

const clients = new Set();
let currentSnapshot = emptySnapshot;
let pairedPublicKey;

function publish(snapshot) {
  currentSnapshot = snapshot;
  const message = `data: ${JSON.stringify(snapshot)}\n\n`;
  for (const client of clients) client.write(message);
}

function contentType(path) {
  if (path.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (path.endsWith('.css')) return 'text/css; charset=utf-8';
  return 'text/html; charset=utf-8';
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function decisionBytes(payload) {
  const fields = [payload.request_id, payload.ask_hash_hex, payload.decision, payload.nonce].map(
    (field) => Buffer.from(field, 'utf8'),
  );
  return Buffer.concat(
    fields.flatMap((field) => {
      const length = Buffer.alloc(4);
      length.writeUInt32BE(field.length);
      return [length, field];
    }),
  );
}

function verifyDecision(payload) {
  if (
    pairedPublicKey === undefined ||
    payload.request_id !== awaiting.request_id ||
    payload.ask_hash_hex !== awaiting.ask_hash_hex ||
    payload.decision !== 'approve' ||
    !/^[0-9a-f]{64}$/.test(payload.nonce ?? '')
  ) {
    return false;
  }

  const signature = Buffer.from(payload.signature_b64 ?? '', 'base64');
  if (signature.length !== 64) return false;
  // SubjectPublicKeyInfo prefix for an uncompressed P-256 point. The browser
  // sends the 65-byte SEC1 point and Noble emits compact r||s signatures.
  const spkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  const key = createPublicKey({
    key: Buffer.concat([spkiPrefix, pairedPublicKey]),
    format: 'der',
    type: 'spki',
  });
  return verify('sha256', decisionBytes(payload), { key, dsaEncoding: 'ieee-p1363' }, signature);
}

function startServer() {
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    if (request.method === 'POST' && url.pathname === '/pair') {
      try {
        const payload = await readJson(request);
        const publicKey = Buffer.from(payload.public_key_b64 ?? '', 'base64');
        if (
          payload.token !== 'recording-pair-token' ||
          payload.nickname !== 'Kitchen iPad' ||
          publicKey.length !== 65 ||
          publicKey[0] !== 4
        ) {
          response.writeHead(400).end('invalid pairing payload');
          return;
        }
        pairedPublicKey = publicKey;
        response.writeHead(204).end();
      } catch {
        response.writeHead(400).end('invalid pairing payload');
      }
      return;
    }
    if (request.method === 'POST' && url.pathname === '/decision') {
      try {
        const payload = await readJson(request);
        if (!verifyDecision(payload)) {
          response.writeHead(403).end('invalid decision signature');
          return;
        }
        setTimeout(() => {
          response.writeHead(204).end();
          setTimeout(() => publish(resolvingSnapshot), 350);
          setTimeout(() => publish(emptySnapshot), 2_100);
        }, 900);
      } catch {
        response.writeHead(400).end('invalid decision payload');
      }
      return;
    }
    if (request.method === 'GET' && url.pathname === '/events') {
      response.writeHead(200, {
        'cache-control': 'no-cache',
        connection: 'keep-alive',
        'content-type': 'text/event-stream',
      });
      clients.add(response);
      response.write(`data: ${JSON.stringify(currentSnapshot)}\n\n`);
      request.on('close', () => clients.delete(response));
      return;
    }

    const publicPath = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const file = normalize(join(DIST, publicPath));
    if (!file.startsWith(`${DIST}/`)) {
      response.writeHead(404).end();
      return;
    }
    try {
      response.writeHead(200, { 'content-type': contentType(file) }).end(readFileSync(file));
    } catch {
      response.writeHead(404).end();
    }
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (typeof address === 'string' || address === null) reject(new Error('missing server port'));
      else resolve({ server, url: `http://127.0.0.1:${address.port}` });
    });
  });
}

async function installVisiblePointer(page) {
  await page.evaluate(() => {
    const style = document.createElement('style');
    style.textContent = `
      #recording-pointer {
        position: fixed; z-index: 9999; left: 0; top: 0; width: 24px; height: 32px;
        pointer-events: none; color: white; filter: drop-shadow(0 2px 3px #000);
        transform: translate(-40px, -40px); transition: transform 700ms cubic-bezier(.2,.8,.2,1);
      }
      #recording-pointer::after {
        content: ''; position: absolute; left: -9px; top: -9px; width: 28px; height: 28px;
        border: 2px solid #aebcff; border-radius: 999px; opacity: 0; transform: scale(.35);
      }
      #recording-pointer.tap::after { animation: recording-tap 480ms ease-out; }
      @keyframes recording-tap { 45% { opacity: .9; } 100% { opacity: 0; transform: scale(1.45); } }
    `;
    const pointer = document.createElement('div');
    pointer.id = 'recording-pointer';
    pointer.setAttribute('aria-hidden', 'true');
    pointer.innerHTML =
      '<svg viewBox="0 0 18 25"><path d="M1 1.2 16.2 14.4 10.1 15.2 13.6 22.2 10.4 23.8 6.9 16.8 1.2 21.2z" fill="currentColor" stroke="#0b0e14" stroke-width="1.6" stroke-linejoin="round"/></svg>';
    document.head.append(style);
    document.body.append(pointer);
  });
}

async function movePointer(page, selector, tap = false) {
  const target = page.locator(selector);
  await target.scrollIntoViewIfNeeded();
  await page.waitForTimeout(350);
  const point = await target.evaluate((element) => {
    const box = element.getBoundingClientRect();
    return { x: box.left + box.width / 2, y: box.top + box.height / 2 };
  });
  await page.locator('#recording-pointer').evaluate(
    (pointer, { point, tap }) => {
      pointer.style.transform = `translate(${point.x}px, ${point.y}px)`;
      pointer.classList.toggle('tap', tap);
    },
    { point, tap },
  );
  await page.mouse.move(point.x, point.y, { steps: 16 });
  await page.waitForTimeout(tap ? 250 : 800);
  if (tap) {
    await page.mouse.click(point.x, point.y);
    await page.waitForTimeout(550);
    await page.locator('#recording-pointer').evaluate((pointer) => pointer.classList.remove('tap'));
  }
}

async function main() {
  mkdirSync(FLOW_ROOT, { recursive: true });
  const videoTemp = join(FLOW_ROOT, '.playwright-video');
  rmSync(videoTemp, { recursive: true, force: true });
  mkdirSync(videoTemp);

  const { server, url } = await startServer();
  let browser;
  try {
    try {
      browser = await chromium.launch({ headless: true });
    } catch (error) {
      throw new Error(
        'Playwright Chromium is missing. Run `pnpm --filter @secreq/link-ui exec playwright install chromium`, then retry.\n' +
          error.message,
      );
    }
    const context = await browser.newContext({
      viewport: VIEWPORT,
      deviceScaleFactor: 1,
      colorScheme: 'dark',
      reducedMotion: 'no-preference',
      recordVideo: { dir: videoTemp, size: VIEWPORT },
    });
    const page = await context.newPage();
    const video = page.video();

    await page.goto(`${url}/#recording-pair-token`);
    await page.locator('h1').getByText('Pair with this host').waitFor();
    await installVisiblePointer(page);
    await page.waitForTimeout(1_200);

    await movePointer(page, 'input[name="nickname"]', true);
    await page.locator('input[name="nickname"]').fill('Kitchen iPad');
    await page.waitForTimeout(700);
    await movePointer(page, 'button.primary', true);
    await page.getByText('Nothing waiting').waitFor();
    await page.waitForTimeout(1_100);

    publish(pendingSnapshot);
    await page.getByText('Awaiting decision').waitFor();
    await page.screenshot({ path: join(FLOW_ROOT, POSTER_NAME) });
    await page.waitForTimeout(2_400);
    await movePointer(page, 'button.primary', true);
    await page.getByText('Signing approval…').waitFor();
    await page.waitForTimeout(450);
    await page.getByText('Resolving…').waitFor();
    await page.waitForTimeout(1_300);
    await page.getByText('Nothing waiting').waitFor();
    await page.waitForTimeout(1_800);

    await context.close();
    await video.saveAs(join(FLOW_ROOT, VIDEO_NAME));
  } finally {
    if (browser) await browser.close();
    for (const client of clients) client.end();
    await new Promise((resolve) => server.close(resolve));
    rmSync(videoTemp, { recursive: true, force: true });
  }

  const metadata = writeMetadata();
  console.log(`recorded ${metadata.id} at ${VIEWPORT.width}x${VIEWPORT.height}`);
}

await main();
