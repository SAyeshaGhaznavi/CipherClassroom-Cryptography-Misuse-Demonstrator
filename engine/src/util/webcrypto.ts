/**
 * Resolves the Web Crypto implementation.
 *
 * In the browser and in Node 20 or newer, globalThis.crypto already is the
 * Web Crypto object. The require() fallback covers older Node builds. The
 * rest of the engine only ever talks to this one function, which keeps the
 * cryptographic modules portable between the API server and the browser.
 */

let cached: Crypto | null = null;

export function getCrypto(): Crypto {
  if (cached !== null) {
    return cached;
  }
  const globalObject = globalThis as unknown as { crypto?: Crypto };
  if (globalObject.crypto !== undefined && globalObject.crypto.subtle !== undefined) {
    cached = globalObject.crypto;
    return cached;
  }
  // Fallback for Node versions that do not expose a global crypto object.
  const nodeCrypto = require('node:crypto') as { webcrypto: Crypto };
  cached = nodeCrypto.webcrypto;
  return cached;
}
