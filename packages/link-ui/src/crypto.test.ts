import { describe, expect, it, vi } from 'vitest';

import { p256 } from '@noble/curves/nist.js';

import { base64ToBytes, generateCredential, signDecision, signedBytes } from './crypto';

describe('linked-device credentials', () => {
  it('keeps the software-managed private key as IndexedDB-ready bytes', async () => {
    const credential = generateCredential();

    expect(credential.privateKey).toBeInstanceOf(Uint8Array);
    expect(credential.privateKey).toHaveLength(32);
    expect(credential.publicKey).toHaveLength(65);
  });

  it('signs the length-prefixed decision contract without Web Crypto', async () => {
    const subtle = vi.spyOn(crypto, 'subtle', 'get').mockImplementation(() => {
      throw new Error('crypto.subtle is unavailable on a plain-HTTP LAN origin');
    });
    try {
      const credential = generateCredential();
      const payload = await signDecision(credential.privateKey, {
        request_id: 'request-123',
        ask_hash_hex: '0123456789abcdef'.repeat(4),
        decision: 'deny',
      });

      const verified = p256.verify(
        base64ToBytes(payload.signature_b64),
        signedBytes(payload),
        credential.publicKey,
      );

      expect(verified).toBe(true);
      expect(base64ToBytes(payload.signature_b64)).toHaveLength(64);
      expect(subtle).not.toHaveBeenCalled();
    } finally {
      subtle.mockRestore();
    }
  });
});
