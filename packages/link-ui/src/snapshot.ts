export const RESOLVING_NUDGE_AFTER_MS = 15_000;

export type RowStatus = 'Awaiting' | 'Resolving' | 'awaiting' | 'resolving';

export interface Caller {
  pid: number;
  name: string;
  command: string;
  exe?: string | null;
}

export interface SecretAsk {
  name: string;
  provider: string;
  locator: string;
  description?: string | null;
  reason?: string | null;
  requested_by?: string[];
  declared_as?: string | null;
}

export interface WrapSubject {
  kind: 'wrap';
  wrap: string;
  cwd: string;
  callers: Caller[];
  callers_truncated?: boolean;
  secrets: SecretAsk[];
  allow_remember: boolean;
}

export interface SshSignSubject {
  kind: 'ssh_sign';
  wrap: string;
  cwd: string;
  callers: Caller[];
  callers_truncated?: boolean;
  info: {
    key_id: string;
    fingerprint: string;
    reason?: string | null;
    anchor?: {
      name: string;
      pid: number;
      kind: 'session' | 'forwarded_ssh';
      command?: string | null;
    } | null;
  };
}

export interface ScopedAgentSubject {
  kind: 'scoped_agent';
  scope: string;
  reference: string;
  guest_chain?: string | null;
  declared_by?: { pid: number; name: string; exe?: string | null } | null;
}

export interface Ask {
  command: string[];
  subject: WrapSubject | SshSignSubject | ScopedAgentSubject;
}

export interface LinkQueueRow {
  request_id: string;
  ask_hash_hex: string;
  representative: Ask;
  status: RowStatus;
  resolving_since?: number;
}

export interface LinkSnapshot {
  queue: LinkQueueRow[];
  link_error?: { message: string };
}

export function isAwaiting(row: LinkQueueRow): boolean {
  return row.status === 'Awaiting' || row.status === 'awaiting';
}

export function newAwaitingRequestIds(previous: LinkQueueRow[], current: LinkQueueRow[]): string[] {
  const previousIds = new Set(previous.map((row) => row.request_id));
  return current
    .filter((row) => isAwaiting(row) && !previousIds.has(row.request_id))
    .map((row) => row.request_id);
}

export function updateResolvingAnchors(
  anchors: Map<string, number>,
  rows: LinkQueueRow[],
  now: number,
  initialSnapshot: boolean,
): void {
  const resolvingIds = new Set<string>();
  for (const row of rows) {
    if (isAwaiting(row)) continue;
    resolvingIds.add(row.request_id);
    if (!anchors.has(row.request_id)) {
      // Once this page has seen the request waiting, client-local elapsed time
      // is authoritative. Only an initial already-resolving row has no local
      // transition to anchor, so it falls back to the daemon fact.
      const startedAt =
        initialSnapshot && row.resolving_since !== undefined ? row.resolving_since : now;
      anchors.set(row.request_id, startedAt);
    }
  }
  for (const requestId of anchors.keys()) {
    if (!resolvingIds.has(requestId)) anchors.delete(requestId);
  }
}

export function resolvingCopy(
  row: LinkQueueRow,
  now = Date.now(),
  anchors?: ReadonlyMap<string, number>,
): string {
  const startedAt = anchors?.get(row.request_id) ?? row.resolving_since;
  if (startedAt === undefined || now - startedAt < RESOLVING_NUDGE_AFTER_MS) {
    return 'Resolving…';
  }
  return "still resolving; if this provider needs a fingerprint or a hardware key, it's waiting for you at the host.";
}
