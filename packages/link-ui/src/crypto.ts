export type Decision = 'approve' | 'deny';

export interface DecisionFields {
  request_id: string;
  ask_hash_hex: string;
  decision: Decision;
}

export interface SignedDecision extends DecisionFields {
  nonce: string;
  signature_b64: string;
}

export async function generateCredential(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
}

export async function signDecision(
  privateKey: CryptoKey,
  fields: DecisionFields,
): Promise<SignedDecision> {
  const payload: SignedDecision = {
    ...fields,
    nonce: randomHex(32),
    signature_b64: '',
  };
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    signedBytes(payload),
  );
  payload.signature_b64 = bytesToBase64(new Uint8Array(signature));
  return payload;
}

export function signedBytes(payload: Pick<SignedDecision, keyof DecisionFields | 'nonce'>) {
  const encoder = new TextEncoder();
  const fields = [payload.request_id, payload.ask_hash_hex, payload.decision, payload.nonce].map(
    (field) => encoder.encode(field),
  );
  const byteLength = fields.reduce((total, field) => total + 4 + field.byteLength, 0);
  const bytes = new Uint8Array(byteLength);
  const view = new DataView(bytes.buffer);
  let offset = 0;

  for (const field of fields) {
    view.setUint32(offset, field.byteLength, false);
    offset += 4;
    bytes.set(field, offset);
    offset += field.byteLength;
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function randomHex(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
