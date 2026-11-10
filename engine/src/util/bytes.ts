/**
 * Byte helpers.
 *
 * Every function below uses a plain loop on purpose. These routines are the
 * evidence behind the nonce reuse and avalanche demonstrations, so being
 * able to read them line by line matters more than being short.
 */

const HEX_DIGITS = '0123456789abcdef';

export function utf8Encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function utf8Decode(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

/**
 * Copies bytes into a standalone ArrayBuffer.
 *
 * Web Crypto expects a BufferSource. Passing a fresh ArrayBuffer avoids the
 * typed array variance problems that appear in recent TypeScript versions
 * and guarantees the view offset is zero.
 */
export function toBuffer(data: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(data.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < data.length; i++) {
    view[i] = data[i];
  }
  return buffer;
}

export function fromBuffer(buffer: ArrayBuffer): Uint8Array {
  const source = new Uint8Array(buffer);
  const out = new Uint8Array(source.length);
  for (let i = 0; i < source.length; i++) {
    out[i] = source[i];
  }
  return out;
}

export function toHex(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i++) {
    const value = data[i];
    out = out + HEX_DIGITS[(value >> 4) & 0x0f];
    out = out + HEX_DIGITS[value & 0x0f];
  }
  return out;
}

export function fromHex(text: string): Uint8Array {
  if (text.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters.');
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    const pair = text.substring(i * 2, i * 2 + 2);
    const value = parseInt(pair, 16);
    if (Number.isNaN(value)) {
      throw new Error('Hex string contains a character that is not a hex digit.');
    }
    out[i] = value;
  }
  return out;
}

/** XOR of two byte arrays, truncated to the shorter of the two. */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  let length = a.length;
  if (b.length < length) {
    length = b.length;
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

/** Number of bits set to one in a single byte. */
export function countSetBitsInByte(value: number): number {
  let remaining = value;
  let count = 0;
  while (remaining !== 0) {
    if ((remaining & 1) === 1) {
      count = count + 1;
    }
    remaining = remaining >>> 1;
  }
  return count;
}

/** Hamming distance in bits between two equal length byte arrays. */
export function hammingDistanceBits(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) {
    throw new Error('Hamming distance requires two arrays of the same length.');
  }
  let total = 0;
  for (let i = 0; i < a.length; i++) {
    total = total + countSetBitsInByte(a[i] ^ b[i]);
  }
  return total;
}

/** Returns a copy with one bit flipped, counting from the most significant bit of byte zero. */
export function flipBit(data: Uint8Array, bitIndex: number): Uint8Array {
  if (bitIndex < 0 || bitIndex >= data.length * 8) {
    throw new Error('Bit index is outside the input.');
  }
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    out[i] = data[i];
  }
  const byteIndex = Math.floor(bitIndex / 8);
  const offsetInByte = bitIndex % 8;
  const mask = 1 << (7 - offsetInByte);
  out[byteIndex] = out[byteIndex] ^ mask;
  return out;
}

/**
 * Comparison that always inspects every byte.
 *
 * A comparison that returns early leaks, through its own running time, how
 * many leading bytes matched. Authentication tag checks use this form.
 */
export function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference = difference | (a[i] ^ b[i]);
  }
  return difference === 0;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  const globalObject = globalThis as unknown as { crypto?: Crypto };
  if (globalObject.crypto !== undefined) {
    globalObject.crypto.getRandomValues(out);
    return out;
  }
  const nodeCrypto = require('node:crypto') as { webcrypto: Crypto };
  nodeCrypto.webcrypto.getRandomValues(out);
  return out;
}

/** Concatenates byte arrays in order. */
export function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (let i = 0; i < parts.length; i++) {
    total = total + parts[i].length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    for (let j = 0; j < part.length; j++) {
      out[offset] = part[j];
      offset = offset + 1;
    }
  }
  return out;
}

/** Shortens a long hex or text value for display, keeping both ends. */
export function shorten(value: string, keep: number): string {
  if (value.length <= keep * 2 + 3) {
    return value;
  }
  return value.substring(0, keep) + '...' + value.substring(value.length - keep);
}
