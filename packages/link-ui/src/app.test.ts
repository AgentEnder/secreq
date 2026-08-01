// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { renderQueue } from './app';
import { RESOLVING_NUDGE_AFTER_MS, type WireQueueRow, type WireSnapshot } from './snapshot';

class FakeEventSource extends EventTarget {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  static instances: FakeEventSource[] = [];

  readonly url: string;
  readonly withCredentials = false;
  readyState = FakeEventSource.CONNECTING;

  constructor(url: string | URL) {
    super();
    this.url = String(url);
    FakeEventSource.instances.push(this);
  }

  close(): void {
    this.readyState = FakeEventSource.CLOSED;
  }
}

function row(status: WireQueueRow['status'], resolvingSince?: number): WireQueueRow {
  return {
    request_id: 'request-1',
    ask_hash_hex: 'a'.repeat(64),
    representative: {
      command: ['deploy'],
      dedupe_key: { wrap: 'deploy' },
      subject: { kind: 'wrap', cwd: '/srv/app', callers: [], secrets: [] },
    },
    status,
    resolving_since: resolvingSince,
    waiter_count: 1,
    first_seen_secs_ago: 0,
  };
}

function publish(source: FakeEventSource, queue: WireQueueRow[]): void {
  const snapshot: WireSnapshot = { queue };
  source.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(snapshot) }));
}

function root(): HTMLElement {
  const root = document.createElement('div');
  document.body.replaceChildren(root);
  renderQueue(root, {
    nickname: 'Test phone',
    privateKey: new Uint8Array(32).fill(1),
  });
  return root;
}

describe('live request rendering', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    FakeEventSource.instances = [];
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    document.body.replaceChildren();
  });

  it('updates a resolving row after the threshold without another snapshot', () => {
    const page = root();
    const source = FakeEventSource.instances[0];
    publish(source, [row('Awaiting')]);
    publish(source, [row('Resolving', Date.now() + 60_000)]);

    const status = page.querySelector<HTMLElement>('[data-resolving-request]');
    expect(status?.textContent).toBe('Resolving…');

    vi.advanceTimersByTime(RESOLVING_NUDGE_AFTER_MS);

    expect(status?.textContent).toBe(
      "still resolving; if this provider needs a fingerprint or a hardware key, it's waiting for you at the host.",
    );
  });

  it('retries a terminally closed event stream with honest connection copy', () => {
    const page = root();
    const source = FakeEventSource.instances[0];
    source.readyState = FakeEventSource.CLOSED;

    source.dispatchEvent(new Event('error'));

    expect(page.querySelector('.connection-status')?.textContent).toBe(
      'The host refused the live connection — too many linked devices are watching. Retrying…',
    );
    expect(FakeEventSource.instances).toHaveLength(1);

    vi.advanceTimersByTime(1_000);

    expect(FakeEventSource.instances).toHaveLength(2);
    expect(FakeEventSource.instances[1].url).toBe('/events');
  });
});
