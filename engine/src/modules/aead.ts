/**
 * FR-3 Authenticated encryption.
 *
 * AES-256-GCM through Web Crypto. GCM verifies an authentication tag during
 * decryption, so any modification of the ciphertext makes decryption fail
 * rather than return wrong plaintext. That failure is the demonstration.
 */

import { getCrypto } from '../util/webcrypto';
import { fromBuffer, toBuffer, utf8Decode, utf8Encode } from '../util/bytes';

export const NONCE_LENGTH_BYTES = 12;
export const TAG_LENGTH_BYTES = 16;
export const KEY_LENGTH_BITS = 256;

export interface DecryptOutcome {
  accepted: boolean;
  plaintext: string | null;
  /** Stable reason, suitable for an audit record. */
  reason: string;
}

export async function generateKeyBytes(): Promise<Uint8Array> {
  const subtleCrypto = getCrypto();
  const key = await subtleCrypto.subtle.generateKey(
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    true,
    ['encrypt', 'decrypt']
  );
  const raw = await subtleCrypto.subtle.exportKey('raw', key as CryptoKey);
  return fromBuffer(raw);
}

export function generateNonce(): Uint8Array {
  const subtleCrypto = getCrypto();
  const nonce = new Uint8Array(NONCE_LENGTH_BYTES);
  subtleCrypto.getRandomValues(nonce);
  return nonce;
}

async function importKey(keyBytes: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  const subtleCrypto = getCrypto();
  return subtleCrypto.subtle.importKey('raw', toBuffer(keyBytes), 'AES-GCM', false, usages);
}

/** Returns ciphertext with the 16 byte authentication tag appended. */
export async function encryptBytes(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const subtleCrypto = getCrypto();
  const key = await importKey(keyBytes, ['encrypt']);
  const parameters: AesGcmParams = {
    name: 'AES-GCM',
    iv: toBuffer(nonce),
    tagLength: TAG_LENGTH_BYTES * 8
  };
  if (additionalData !== undefined) {
    parameters.additionalData = toBuffer(additionalData);
  }
  const encrypted = await subtleCrypto.subtle.encrypt(parameters, key, toBuffer(plaintext));
  return fromBuffer(encrypted);
}

export async function encryptText(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  plaintext: string,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  return encryptBytes(keyBytes, nonce, utf8Encode(plaintext), additionalData);
}

/**
 * Attempts decryption. A failed tag check is an expected outcome here, not
 * an internal error, so it is reported rather than thrown.
 */
export async function decryptText(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  additionalData?: Uint8Array
): Promise<DecryptOutcome> {
  const subtleCrypto = getCrypto();
  if (ciphertextWithTag.length < TAG_LENGTH_BYTES) {
    return {
      accepted: false,
      plaintext: null,
      reason: 'Ciphertext is shorter than the authentication tag, so it cannot be genuine.'
    };
  }
  try {
    const key = await importKey(keyBytes, ['decrypt']);
    const parameters: AesGcmParams = {
      name: 'AES-GCM',
      iv: toBuffer(nonce),
      tagLength: TAG_LENGTH_BYTES * 8
    };
    if (additionalData !== undefined) {
      parameters.additionalData = toBuffer(additionalData);
    }
    const decrypted = await subtleCrypto.subtle.decrypt(parameters, key, toBuffer(ciphertextWithTag));
    return {
      accepted: true,
      plaintext: utf8Decode(fromBuffer(decrypted)),
      reason: 'Authentication tag verified and the message decrypted unchanged.'
    };
  } catch (error) {
    return {
      accepted: false,
      plaintext: null,
      reason: 'Authentication tag did not verify, so the message was rejected without being returned.'
    };
  }
}

/** Returns a copy with one bit of one byte flipped, for the tampering test. */
export function tamperWithByte(data: Uint8Array, byteIndex: number, mask: number): Uint8Array {
  if (byteIndex < 0 || byteIndex >= data.length) {
    throw new Error('Cannot tamper with a byte outside the message.');
  }
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i];
  }
  out[byteIndex] = out[byteIndex] ^ mask;
  return out;
}

export interface TamperReport {
  originalAccepted: boolean;
  tamperedAccepted: boolean;
  tamperedByteIndex: number;
  reason: string;
}

/**
 * Encrypts, decrypts, then flips one bit of the ciphertext and tries again.
 * A correct implementation accepts the first and rejects the second.
 */
export async function runTamperCheck(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  plaintext: string,
  byteIndex: number
): Promise<TamperReport & { ciphertext: Uint8Array; tampered: Uint8Array }> {
  const ciphertext = await encryptText(keyBytes, nonce, plaintext);
  const original = await decryptText(keyBytes, nonce, ciphertext);
  const tampered = tamperWithByte(ciphertext, byteIndex, 0x01);
  const modified = await decryptText(keyBytes, nonce, tampered);
  return {
    originalAccepted: original.accepted,
    tamperedAccepted: modified.accepted,
    tamperedByteIndex: byteIndex,
    reason: modified.reason,
    ciphertext: ciphertext,
    tampered: tampered
  };
}
