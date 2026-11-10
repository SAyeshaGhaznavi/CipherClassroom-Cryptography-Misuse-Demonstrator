/**
 * FR-6 Test vector checker.
 *
 * Runs the engine against published values from FIPS 180-4, RFC 7914,
 * RFC 6070 and the NIST GCM specification. Checking against an outside
 * source is what separates a working implementation from one that merely
 * agrees with itself.
 */

import type { TestResult } from '../types';
import type { VectorSet } from '../../fixtures';
import { fromHex, toHex, utf8Encode } from '../util/bytes';
import { sha256 } from './hashing';
import { deriveKeyPbkdf2 } from './hashing';
import { encryptBytes } from './aead';
import { caesarEncrypt, vigenereEncrypt } from './classical';
import { shorten } from '../util/bytes';

export interface VectorRunSummary {
  results: TestResult[];
  passed: number;
  failed: number;
  total: number;
  passRate: number;
}

function record(name: string, expected: string, actual: string): TestResult {
  return {
    name: name,
    expected: expected,
    actual: actual,
    passed: expected === actual
  };
}

/** Runs every vector in the supplied set and returns one result per vector. */
export async function runTestVectors(vectors: VectorSet): Promise<VectorRunSummary> {
  const results: TestResult[] = [];

  for (let i = 0; i < vectors.sha256.length; i++) {
    const vector = vectors.sha256[i];
    const digest = await sha256(utf8Encode(vector.inputUtf8));
    results.push(record(vector.name, vector.expectedHex, toHex(digest)));
  }

  for (let i = 0; i < vectors.pbkdf2Sha256.length; i++) {
    const vector = vectors.pbkdf2Sha256[i];
    const outcome = await deriveKeyPbkdf2(
      vector.password,
      utf8Encode(vector.saltUtf8),
      vector.iterations,
      vector.outputBits
    );
    results.push(record(vector.name, vector.expectedHex, toHex(outcome.derivedKey)));
  }

  for (let i = 0; i < vectors.aesGcm.length; i++) {
    const vector = vectors.aesGcm[i];
    const key = fromHex(vector.keyHex);
    const nonce = fromHex(vector.nonceHex);
    const plaintext = fromHex(vector.plaintextHex);
    const produced = await encryptBytes(key, nonce, plaintext);
    results.push(record(vector.name, vector.expectedCiphertextWithTagHex, toHex(produced)));
  }

  for (let i = 0; i < vectors.classical.length; i++) {
    const vector = vectors.classical[i];
    let produced = '';
    if (vector.algorithm === 'caesar') {
      let shift = 0;
      if (vector.shift !== undefined) {
        shift = vector.shift;
      }
      produced = caesarEncrypt(vector.inputText, shift);
    } else {
      let keyword = 'A';
      if (vector.keyword !== undefined) {
        keyword = vector.keyword;
      }
      produced = vigenereEncrypt(vector.inputText, keyword);
    }
    results.push(record(vector.name, vector.expectedText, produced));
  }

  let passed = 0;
  let failed = 0;
  for (let i = 0; i < results.length; i++) {
    if (results[i].passed) {
      passed = passed + 1;
    } else {
      failed = failed + 1;
    }
  }

  let rate = 0;
  if (results.length > 0) {
    rate = Math.round((passed / results.length) * 10000) / 100;
  }

  return { results: results, passed: passed, failed: failed, total: results.length, passRate: rate };
}

/** Compact one line form of a vector result, for display and for the report. */
export function describeResult(result: TestResult): string {
  let status = 'FAIL';
  if (result.passed) {
    status = 'PASS';
  }
  return status + ' | ' + result.name + ' | expected ' + shorten(result.expected, 12) + ' | actual ' + shorten(result.actual, 12);
}
