import { describe, expect, it } from 'vitest';

import { base64ToBytes, generateCredential, signDecision, signedBytes } from './crypto';

describe('linked-device credentials', () => {
  it('generates a non-extractable private key', async () => {
    const credential = await generateCredential();

    expect(credential.privateKey.extractable).toBe(false);
    expect(credential.publicKey.extractable).toBe(true);
  });

  it('signs the length-prefixed decision contract the daemon verifies', async () => {
    const credential = await generateCredential();
    const payload = await signDecision(credential.privateKey, {
      request_id: 'request-123',
      ask_hash_hex: '0123456789abcdef'.repeat(4),
      decision: 'deny',
    });

    const verified = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      credential.publicKey,
      base64ToBytes(payload.signature_b64),
      signedBytes(payload),
    );

    expect(verified).toBe(true);
    expect(base64ToBytes(payload.signature_b64)).toHaveLength(64);
  });
});
