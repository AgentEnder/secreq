export const RESOLVING_NUDGE_AFTER_MS = 15_000;

export type RowStatus = 'Awaiting' | 'Resolving' | 'awaiting' | 'resolving';

export interface Caller {
  pid: number;
  name: string;
  command: string;
  exe?: string;
}

export interface SecretAsk {
  name: string;
  provider: string;
  locator: string;
  description?: string;
  reason?: string;
  requested_by?: string[];
  declared_as?: string;
}

export interface WrapSubject {
  kind: 'wrap';
  cwd: string;
  callers: Caller[];
  callers_truncated?: boolean;
  secrets: SecretAsk[];
  allow_remember?: boolean;
}

export interface SshSignSubject {
  kind: 'ssh_sign';
  cwd: string;
  callers: Caller[];
  callers_truncated?: boolean;
  info: {
    key_id: string;
    fingerprint: string;
    reason?: string;
    anchor?: { name: string; pid: number; kind: string; command?: string };
  };
}

export interface ScopedAgentSubject {
  kind: 'scoped_agent';
  scope: string;
  reference: string;
  guest_chain?: string;
  declared_by?: { pid: number; name: string; exe?: string };
}

export interface Ask {
  command: string[];
  dedupe_key: { wrap: string };
  subject: WrapSubject | SshSignSubject | ScopedAgentSubject;
}

export interface WireQueueRow {
  request_id: string;
  ask_hash_hex: string;
  representative: Ask;
  waiter_count: number;
  first_seen_secs_ago: number;
  status: RowStatus;
  resolving_since?: number;
}

export interface WireSnapshot {
  queue: WireQueueRow[];
  link_error?: { request_id: string; message: string };
}

export function isAwaiting(row: WireQueueRow): boolean {
  return row.status === 'Awaiting' || row.status === 'awaiting';
}

export function newAwaitingRequestIds(previous: WireQueueRow[], current: WireQueueRow[]): string[] {
  const previousIds = new Set(previous.map((row) => row.request_id));
  return current
    .filter((row) => isAwaiting(row) && !previousIds.has(row.request_id))
    .map((row) => row.request_id);
}

export function resolvingCopy(row: WireQueueRow, now = Date.now()): string {
  if (row.resolving_since === undefined || now - row.resolving_since < RESOLVING_NUDGE_AFTER_MS) {
    return 'Resolving…';
  }
  return "still resolving; if this provider needs a fingerprint or a hardware key, it's waiting for you at the host.";
}
