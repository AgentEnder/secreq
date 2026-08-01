import { describe, expect, it } from 'vitest';

import {
  RESOLVING_NUDGE_AFTER_MS,
  newAwaitingRequestIds,
  resolvingCopy,
  updateResolvingAnchors,
  type WireQueueRow,
} from './snapshot';

function row(requestId: string, status: WireQueueRow['status'] = 'Awaiting'): WireQueueRow {
  return {
    request_id: requestId,
    ask_hash_hex: 'a'.repeat(64),
    representative: {
      command: ['deploy'],
      dedupe_key: { wrap: 'deploy' },
      subject: { kind: 'wrap', cwd: '/srv/app', callers: [], secrets: [] },
    },
    status,
    resolving_since: status === 'Resolving' ? 1_000 : undefined,
    waiter_count: 1,
    first_seen_secs_ago: 0,
  };
}

describe('pending snapshots', () => {
  it('nudges only for newly-arrived awaiting requests', () => {
    expect(newAwaitingRequestIds([row('old')], [row('old'), row('new')])).toEqual(['new']);
    expect(newAwaitingRequestIds([], [row('resolving', 'Resolving')])).toEqual([]);
  });

  it('uses the host-interaction wording past the resolving threshold', () => {
    const resolving = row('request', 'Resolving');

    expect(resolvingCopy(resolving, 1_000 + RESOLVING_NUDGE_AFTER_MS - 1)).toBe('Resolving…');
    expect(resolvingCopy(resolving, 1_000 + RESOLVING_NUDGE_AFTER_MS)).toBe(
      "still resolving; if this provider needs a fingerprint or a hardware key, it's waiting for you at the host.",
    );
  });

  it('anchors a newly resolving row to client time despite host clock skew', () => {
    const anchors = new Map<string, number>();
    const clientNow = 100_000;
    const resolving = row('request', 'Resolving');
    resolving.resolving_since = clientNow + 60_000;

    updateResolvingAnchors(anchors, [resolving], clientNow, false);

    expect(resolvingCopy(resolving, clientNow + RESOLVING_NUDGE_AFTER_MS - 1, anchors)).toBe(
      'Resolving…',
    );
    expect(resolvingCopy(resolving, clientNow + RESOLVING_NUDGE_AFTER_MS, anchors)).toContain(
      'still resolving',
    );
  });

  it('uses the daemon timestamp only for a row already resolving initially', () => {
    const anchors = new Map<string, number>();
    const resolving = row('request', 'Resolving');

    updateResolvingAnchors(anchors, [resolving], 50_000, true);

    expect(anchors.get('request')).toBe(resolving.resolving_since);
  });
});
