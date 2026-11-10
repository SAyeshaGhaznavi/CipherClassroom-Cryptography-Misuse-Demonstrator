/**
 * FR-5 Nonce reuse demonstration.
 *
 * AES-GCM builds a keystream from the key and the nonce, then XORs that
 * keystream with the plaintext. Encrypting two messages under the same key
 * and the same nonce produces the same keystream twice, so:
 *
 *   C1 XOR C2 = (P1 XOR K) XOR (P2 XOR K) = P1 XOR P2
 *
 * The key cancels out. Anyone holding both ciphertexts learns the XOR of
 * the two plaintexts, and anyone who also knows one plaintext recovers the
 * other exactly. This module proves both statements with measured values.
 *
 * This is a deliberately unsafe construction shown for teaching. The key
 * and nonce are generated locally and nothing leaves the process.
 */

import { encryptText, generateKeyBytes, generateNonce, TAG_LENGTH_BYTES } from './aead';
import { constantTimeEquals, toHex, utf8Decode, utf8Encode, xorBytes } from '../util/bytes';

export interface NonceReuseEvidence {
  firstCiphertextHex: string;
  secondCiphertextHex: string;
  ciphertextXorHex: string;
  plaintextXorHex: string;
  /** True when C1 XOR C2 equals P1 XOR P2, which is the leak itself. */
  relationshipHolds: boolean;
  /** Second message recovered from the first plus the two ciphertexts. */
  recoveredSecondMessage: string;
  recoveryExact: boolean;
  nonceHex: string;
  messageLengthBytes: number;
}

/** Strips the trailing 16 byte authentication tag to leave the keystream part. */
export function stripTag(ciphertextWithTag: Uint8Array): Uint8Array {
  const length = ciphertextWithTag.length - TAG_LENGTH_BYTES;
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = ciphertextWithTag[i];
  }
  return out;
}

/**
 * Encrypts two equal length messages under one key and one nonce, then
 * shows the relationship and recovers the second message from the first.
 */
export async function demonstrateNonceReuse(
  firstMessage: string,
  secondMessage: string
): Promise<NonceReuseEvidence> {
  const firstBytes = utf8Encode(firstMessage);
  const secondBytes = utf8Encode(secondMessage);
  if (firstBytes.length !== secondBytes.length) {
    throw new Error('Both messages must have the same length in bytes for this demonstration.');
  }

  const keyBytes = await generateKeyBytes();
  const nonce = generateNonce();

  // The mistake being demonstrated: the same nonce used twice.
  const firstCipher = stripTag(await encryptText(keyBytes, nonce, firstMessage));
  const secondCipher = stripTag(await encryptText(keyBytes, nonce, secondMessage));

  const ciphertextXor = xorBytes(firstCipher, secondCipher);
  const plaintextXor = xorBytes(firstBytes, secondBytes);
  const relationshipHolds = constantTimeEquals(ciphertextXor, plaintextXor);

  // Recovery: knowing P1, compute P1 XOR (C1 XOR C2) to obtain P2.
  const recoveredBytes = xorBytes(firstBytes, ciphertextXor);
  const recoveredText = utf8Decode(recoveredBytes);
  const recoveryExact = constantTimeEquals(recoveredBytes, secondBytes);

  return {
    firstCiphertextHex: toHex(firstCipher),
    secondCiphertextHex: toHex(secondCipher),
    ciphertextXorHex: toHex(ciphertextXor),
    plaintextXorHex: toHex(plaintextXor),
    relationshipHolds: relationshipHolds,
    recoveredSecondMessage: recoveredText,
    recoveryExact: recoveryExact,
    nonceHex: toHex(nonce),
    messageLengthBytes: firstBytes.length
  };
}

export interface FreshNonceComparison {
  firstCiphertextHex: string;
  secondCiphertextHex: string;
  ciphertextXorHex: string;
  plaintextXorHex: string;
  relationshipHolds: boolean;
}

/**
 * The control case. With a fresh nonce for each message the relationship
 * disappears, which is what shows the leak is caused by nonce reuse and not
 * by the cipher itself.
 */
export async function compareWithFreshNonces(
  firstMessage: string,
  secondMessage: string
): Promise<FreshNonceComparison> {
  const firstBytes = utf8Encode(firstMessage);
  const secondBytes = utf8Encode(secondMessage);
  const keyBytes = await generateKeyBytes();
  const firstNonce = generateNonce();
  const secondNonce = generateNonce();

  const firstCipher = stripTag(await encryptText(keyBytes, firstNonce, firstMessage));
  const secondCipher = stripTag(await encryptText(keyBytes, secondNonce, secondMessage));

  const ciphertextXor = xorBytes(firstCipher, secondCipher);
  const plaintextXor = xorBytes(firstBytes, secondBytes);

  return {
    firstCiphertextHex: toHex(firstCipher),
    secondCiphertextHex: toHex(secondCipher),
    ciphertextXorHex: toHex(ciphertextXor),
    plaintextXorHex: toHex(plaintextXor),
    relationshipHolds: constantTimeEquals(ciphertextXor, plaintextXor)
  };
}
