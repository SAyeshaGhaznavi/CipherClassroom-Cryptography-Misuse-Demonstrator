/**
 * FR-4 Hashing and key derivation functions.
 *
 * SHA-256 is fast on purpose, which is exactly why it is the wrong tool for
 * storing passwords on its own. PBKDF2 adds a salt and a cost parameter.
 * This module measures that cost so the difference can be shown rather than
 * asserted.
 */

import { getCrypto } from '../util/webcrypto';
import { fromBuffer, toBuffer, toHex, utf8Encode } from '../util/bytes';
import type { LabPolicy } from '../policy';
import type { Severity } from '../types';

export const SALT_LENGTH_BYTES = 16;
export const DERIVED_KEY_BITS = 256;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const subtleCrypto = getCrypto();
  const digest = await subtleCrypto.subtle.digest('SHA-256', toBuffer(data));
  return fromBuffer(digest);
}

export async function sha256Text(text: string): Promise<Uint8Array> {
  return sha256(utf8Encode(text));
}

export async function sha256HexText(text: string): Promise<string> {
  const digest = await sha256Text(text);
  return toHex(digest);
}

export function generateSalt(): Uint8Array {
  const subtleCrypto = getCrypto();
  const salt = new Uint8Array(SALT_LENGTH_BYTES);
  subtleCrypto.getRandomValues(salt);
  return salt;
}

export interface DerivationOutcome {
  derivedKey: Uint8Array;
  iterations: number;
  saltHex: string;
  elapsedMs: number;
}

/** PBKDF2 with HMAC-SHA-256. Timing is measured so cost can be compared. */
export async function deriveKeyPbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  lengthBits?: number
): Promise<DerivationOutcome> {
  const subtleCrypto = getCrypto();
  const outputBits = lengthBits === undefined ? DERIVED_KEY_BITS : lengthBits;
  const baseKey = await subtleCrypto.subtle.importKey(
    'raw',
    toBuffer(utf8Encode(password)),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const startedAt = Date.now();
  const derived = await subtleCrypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: toBuffer(salt), iterations: iterations },
    baseKey,
    outputBits
  );
  const elapsed = Date.now() - startedAt;
  return {
    derivedKey: fromBuffer(derived),
    iterations: iterations,
    saltHex: toHex(salt),
    elapsedMs: elapsed
  };
}

export interface CostAssessment {
  severity: Severity;
  warnings: string[];
  reasons: string[];
  /**
   * Rough number of guesses per second an attacker with a single machine
   * could make at this cost, based on the measured time for one derivation.
   */
  estimatedGuessesPerSecond: number;
}

/**
 * Applies the lab policy to a measured derivation.
 *
 * The thresholds come from the policy object rather than from constants in
 * this file, so an administrator can change one and repeat the test.
 */
export function assessKdfCost(outcome: DerivationOutcome, policy: LabPolicy): CostAssessment {
  const warnings: string[] = [];
  const reasons: string[] = [];
  let severity: Severity = 'info';

  let guessesPerSecond = 0;
  if (outcome.elapsedMs > 0) {
    guessesPerSecond = Math.round(1000 / outcome.elapsedMs);
  } else {
    // Faster than the clock resolution, which is itself the finding.
    guessesPerSecond = 1000;
  }

  if (outcome.iterations < policy.criticalKdfIterations) {
    severity = 'critical';
    warnings.push(
      'The iteration count of ' +
        outcome.iterations +
        ' is far below the configured minimum of ' +
        policy.minSafeKdfIterations +
        '. Password guessing against this setting is cheap.'
    );
    reasons.push('iterations < criticalKdfIterations (' + policy.criticalKdfIterations + ')');
  } else if (outcome.iterations < policy.minSafeKdfIterations) {
    severity = 'warning';
    warnings.push(
      'The iteration count of ' +
        outcome.iterations +
        ' is below the configured minimum of ' +
        policy.minSafeKdfIterations +
        '.'
    );
    reasons.push('iterations < minSafeKdfIterations (' + policy.minSafeKdfIterations + ')');
  } else {
    reasons.push('iterations >= minSafeKdfIterations (' + policy.minSafeKdfIterations + ')');
  }

  return {
    severity: severity,
    warnings: warnings,
    reasons: reasons,
    estimatedGuessesPerSecond: guessesPerSecond
  };
}

export interface CostComparison {
  weak: DerivationOutcome;
  strong: DerivationOutcome;
  /** How many times longer the stronger setting took. */
  slowdownFactor: number;
}

/** Derives the same password at two costs so the two timings sit side by side. */
export async function compareKdfCost(
  password: string,
  salt: Uint8Array,
  weakIterations: number,
  strongIterations: number
): Promise<CostComparison> {
  const weak = await deriveKeyPbkdf2(password, salt, weakIterations);
  const strong = await deriveKeyPbkdf2(password, salt, strongIterations);
  let factor = 0;
  if (weak.elapsedMs > 0) {
    factor = Math.round((strong.elapsedMs / weak.elapsedMs) * 10) / 10;
  } else {
    factor = strong.elapsedMs;
  }
  return { weak: weak, strong: strong, slowdownFactor: factor };
}

/**
 * Demonstrates why an unsalted fast hash is unsuitable for passwords: the
 * same password always produces the same digest, so one precomputed table
 * breaks every account at once.
 */
export async function demonstrateUnsaltedCollisionRisk(passwords: string[]): Promise<string[]> {
  const digests: string[] = [];
  for (let i = 0; i < passwords.length; i++) {
    const digest = await sha256HexText(passwords[i]);
    digests.push(digest);
  }
  return digests;
}
