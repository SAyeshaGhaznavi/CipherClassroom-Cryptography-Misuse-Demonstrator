/**
 * Avalanche measurement, required by evaluation case T5.
 *
 * A strong hash should behave like a random function: flipping one input
 * bit should change about half of the output bits. For SHA-256 that is
 * around 128 of 256. The measurement below reports the real number rather
 * than repeating the claim.
 */

import { sha256 } from './hashing';
import { flipBit, hammingDistanceBits, toHex, utf8Encode } from '../util/bytes';
import type { LabPolicy } from '../policy';

export interface SingleAvalancheMeasurement {
  bitIndex: number;
  originalDigestHex: string;
  mutatedDigestHex: string;
  changedBits: number;
  changedPercent: number;
}

export async function measureSingleFlip(text: string, bitIndex: number): Promise<SingleAvalancheMeasurement> {
  const original = utf8Encode(text);
  const mutated = flipBit(original, bitIndex);
  const originalDigest = await sha256(original);
  const mutatedDigest = await sha256(mutated);
  const changed = hammingDistanceBits(originalDigest, mutatedDigest);
  return {
    bitIndex: bitIndex,
    originalDigestHex: toHex(originalDigest),
    mutatedDigestHex: toHex(mutatedDigest),
    changedBits: changed,
    changedPercent: Math.round((changed / 256) * 10000) / 100
  };
}

export interface AvalancheReport {
  samples: SingleAvalancheMeasurement[];
  averageChangedBits: number;
  minimumChangedBits: number;
  maximumChangedBits: number;
  averagePercent: number;
  withinPolicyBand: boolean;
  bandLow: number;
  bandHigh: number;
}

/**
 * Flips each of the first `sampleCount` input bits in turn and averages the
 * result. Averaging matters: a single flip can land away from 128 by chance,
 * so one sample is not evidence on its own.
 */
export async function measureAvalanche(
  text: string,
  sampleCount: number,
  policy: LabPolicy
): Promise<AvalancheReport> {
  const inputBits = utf8Encode(text).length * 8;
  let limit = sampleCount;
  if (limit > inputBits) {
    limit = inputBits;
  }
  if (limit < 1) {
    throw new Error('Avalanche measurement needs at least one input bit.');
  }

  const samples: SingleAvalancheMeasurement[] = [];
  let total = 0;
  let minimum = 256;
  let maximum = 0;

  for (let bitIndex = 0; bitIndex < limit; bitIndex++) {
    const sample = await measureSingleFlip(text, bitIndex);
    samples.push(sample);
    total = total + sample.changedBits;
    if (sample.changedBits < minimum) {
      minimum = sample.changedBits;
    }
    if (sample.changedBits > maximum) {
      maximum = sample.changedBits;
    }
  }

  const average = total / samples.length;
  const roundedAverage = Math.round(average * 100) / 100;
  const withinBand = roundedAverage >= policy.minAvalancheBits && roundedAverage <= policy.maxAvalancheBits;

  return {
    samples: samples,
    averageChangedBits: roundedAverage,
    minimumChangedBits: minimum,
    maximumChangedBits: maximum,
    averagePercent: Math.round((average / 256) * 10000) / 100,
    withinPolicyBand: withinBand,
    bandLow: policy.minAvalancheBits,
    bandHigh: policy.maxAvalancheBits
  };
}

/**
 * The contrast case. A Caesar shift has no avalanche at all: changing one
 * input character changes exactly one output character and nothing else.
 */
export function measureClassicalAvalanche(text: string, shift: number): { changedCharacters: number; total: number } {
  if (text.length === 0) {
    return { changedCharacters: 0, total: 0 };
  }
  const firstCharacter = text[0];
  let replacement = 'a';
  if (firstCharacter === 'a') {
    replacement = 'b';
  }
  const mutatedText = replacement + text.substring(1);

  let original = '';
  let mutated = '';
  for (let i = 0; i < text.length; i++) {
    original = original + shiftCharacter(text[i], shift);
    mutated = mutated + shiftCharacter(mutatedText[i], shift);
  }

  let changed = 0;
  for (let i = 0; i < original.length; i++) {
    if (original[i] !== mutated[i]) {
      changed = changed + 1;
    }
  }
  return { changedCharacters: changed, total: original.length };
}

function shiftCharacter(character: string, shift: number): string {
  const code = character.charCodeAt(0);
  if (code >= 65 && code <= 90) {
    return String.fromCharCode(65 + ((code - 65 + shift) % 26));
  }
  if (code >= 97 && code <= 122) {
    return String.fromCharCode(97 + ((code - 97 + shift) % 26));
  }
  return character;
}
