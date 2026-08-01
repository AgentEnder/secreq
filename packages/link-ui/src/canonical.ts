import { sha256 } from '@noble/hashes/sha2.js';

import type { Ask, Caller, SecretAsk } from './snapshot';

const CONTRACT = 'secreq-link-ask-v1';
const encoder = new TextEncoder();

/**
 * Recompute the exact length-prefixed v1 hash Rust signs decisions against.
 * This is intentionally explicit rather than JSON serialization: object key
 * order, omitted optional fields, and future local-only fields are not part of
 * the approval contract.
 */
export function canonicalAskHash(ask: Ask): string {
  return bytesToHex(sha256(canonicalAskBytes(ask)));
}

/** Return the browser-computed hash only when the daemon's claim agrees. */
export function verifiedAskHash(ask: Ask, suppliedHash: string): string {
  const computedHash = canonicalAskHash(ask);
  if (computedHash !== suppliedHash) {
    throw new Error(
      'The request details do not match the host hash. Refusing to sign; wait for the host to refresh.',
    );
  }
  return computedHash;
}

function canonicalAskBytes(ask: Ask): Uint8Array {
  const writer = new CanonicalWriter();
  writer.part(CONTRACT);
  writer.strings('command', ask.command);

  const subject = ask.subject;
  switch (subject.kind) {
    case 'wrap':
      writer.part('wrap');
      writer.field('wrap', subject.wrap);
      writer.field('cwd', subject.cwd);
      writer.bool('callers_truncated', subject.callers_truncated ?? false);
      writer.callers(subject.callers);
      writer.count('secrets', subject.secrets.length);
      for (const secret of subject.secrets) writer.secret(secret);
      writer.bool('allow_remember', subject.allow_remember);
      break;
    case 'ssh_sign':
      writer.part('ssh_sign');
      writer.field('wrap', subject.wrap);
      writer.field('cwd', subject.cwd);
      writer.bool('callers_truncated', subject.callers_truncated ?? false);
      writer.callers(subject.callers);
      writer.field('key_id', subject.info.key_id);
      writer.field('fingerprint', subject.info.fingerprint);
      writer.option('reason', subject.info.reason);
      if (subject.info.anchor) {
        const anchor = subject.info.anchor;
        writer.part('anchor_some');
        writer.field('anchor_name', anchor.name);
        writer.number('anchor_pid', anchor.pid);
        writer.field('anchor_kind', anchor.kind);
        writer.option('anchor_command', anchor.command);
      } else {
        writer.part('anchor_none');
      }
      break;
    case 'scoped_agent':
      writer.part('scoped_agent');
      writer.field('scope', subject.scope);
      writer.field('reference', subject.reference);
      writer.option('guest_chain', subject.guest_chain);
      if (subject.declared_by) {
        const peer = subject.declared_by;
        writer.part('declared_by_some');
        writer.number('declared_by_pid', peer.pid);
        writer.field('declared_by_name', peer.name);
        writer.option('declared_by_exe', peer.exe);
      } else {
        writer.part('declared_by_none');
      }
      break;
  }

  return writer.finish();
}

class CanonicalWriter {
  readonly #chunks: Uint8Array[] = [];
  #length = 0;

  part(part: string): void {
    const bytes = encoder.encode(part);
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, bytes.length, false);
    this.#chunks.push(length, bytes);
    this.#length += length.length + bytes.length;
  }

  field(name: string, value: string): void {
    this.part(name);
    this.part(value);
  }

  number(name: string, value: number): void {
    this.field(name, String(value));
  }

  bool(name: string, value: boolean): void {
    this.field(name, value ? 'true' : 'false');
  }

  option(name: string, value: string | null | undefined): void {
    this.part(name);
    if (value === undefined || value === null) {
      this.part('none');
    } else {
      this.part('some');
      this.part(value);
    }
  }

  count(name: string, count: number): void {
    this.number(name, count);
  }

  strings(name: string, values: string[]): void {
    this.count(name, values.length);
    for (const value of values) this.part(value);
  }

  callers(callers: Caller[]): void {
    this.count('callers', callers.length);
    for (const caller of callers) {
      this.number('caller_pid', caller.pid);
      this.field('caller_name', caller.name);
      this.field('caller_command', caller.command);
      this.option('caller_exe', caller.exe);
    }
  }

  secret(secret: SecretAsk): void {
    this.field('secret_name', secret.name);
    this.field('secret_provider', secret.provider);
    this.field('secret_locator', secret.locator);
    this.option('secret_description', secret.description);
    this.option('secret_reason', secret.reason);
    this.strings('secret_requested_by', secret.requested_by ?? []);
    this.option('secret_declared_as', secret.declared_as);
  }

  finish(): Uint8Array {
    const bytes = new Uint8Array(this.#length);
    let offset = 0;
    for (const chunk of this.#chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return bytes;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
