/**
 * Server side input validation and normalization.
 *
 * Nothing reaches a cryptographic module until it has passed through here.
 * Every rejection carries a stable error code and a message that is safe to
 * show to the user.
 */

import { EngineError } from '../errors';
import type { LabPolicy } from '../policy';
import type { ExperimentType } from '../types';

const SUPPORTED_TYPES: ExperimentType[] = [
  'classical-cipher',
  'authenticated-encryption',
  'hashing-kdfs',
  'nonce-reuse',
  'test-vectors',
  'avalanche'
];

/** Control characters other than tab and newline are rejected outright. */
function containsDisallowedControlCharacters(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code === 9 || code === 10) {
      continue;
    }
    if (code < 32 || code === 127) {
      return true;
    }
  }
  return false;
}

/**
 * Normalizes accepted text: Unicode NFC form, carriage returns removed, and
 * surrounding whitespace trimmed. Only normalized data moves to the next
 * stage of the workflow.
 */
export function normalizeText(text: string): string {
  let normalized = text.normalize('NFC');
  let withoutCarriageReturns = '';
  for (let i = 0; i < normalized.length; i++) {
    if (normalized.charCodeAt(i) !== 13) {
      withoutCarriageReturns = withoutCarriageReturns + normalized[i];
    }
  }
  return withoutCarriageReturns.trim();
}

export function validateText(value: unknown, policy: LabPolicy, fieldName: string): string {
  if (typeof value !== 'string') {
    throw new EngineError('INVALID_INPUT', fieldName + ' must be text.');
  }
  if (value.length > policy.maxInputLength) {
    throw new EngineError(
      'INPUT_TOO_LARGE',
      fieldName + ' must be ' + policy.maxInputLength + ' characters or fewer.'
    );
  }
  if (containsDisallowedControlCharacters(value)) {
    throw new EngineError('INVALID_INPUT', fieldName + ' contains control characters that are not allowed.');
  }
  const normalized = normalizeText(value);
  if (normalized.length === 0) {
    throw new EngineError('INVALID_INPUT', fieldName + ' cannot be empty.');
  }
  return normalized;
}

export function validateShift(value: unknown): number {
  if (value === undefined || value === null) {
    return 3;
  }
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new EngineError('INVALID_PARAMETER', 'Shift must be a whole number.');
  }
  if (value < 0 || value > 25) {
    throw new EngineError('INVALID_PARAMETER', 'Shift must be between 0 and 25.');
  }
  return value;
}

export function validateIterations(value: unknown, policy: LabPolicy): number {
  if (value === undefined || value === null) {
    return policy.minSafeKdfIterations;
  }
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new EngineError('INVALID_PARAMETER', 'Iteration count must be a whole number.');
  }
  if (value < 1) {
    throw new EngineError('INVALID_PARAMETER', 'Iteration count must be at least 1.');
  }
  if (value > policy.maxKdfIterations) {
    throw new EngineError(
      'INVALID_PARAMETER',
      'Iteration count must be ' + policy.maxKdfIterations + ' or fewer so the lab stays responsive.'
    );
  }
  return value;
}

/** Vigenere keywords are letters only, normalized to upper case. */
export function validateKeyword(value: unknown): string {
  if (typeof value !== 'string') {
    throw new EngineError('INVALID_PARAMETER', 'A keyword is required for the Vigenere cipher.');
  }
  const trimmed = value.trim().toUpperCase();
  if (trimmed.length === 0) {
    throw new EngineError('INVALID_PARAMETER', 'The keyword cannot be empty.');
  }
  if (trimmed.length > 64) {
    throw new EngineError('INVALID_PARAMETER', 'The keyword must be 64 characters or fewer.');
  }
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i);
    if (code < 65 || code > 90) {
      throw new EngineError('INVALID_PARAMETER', 'The keyword must contain letters A to Z only.');
    }
  }
  return trimmed;
}

export function validateType(value: unknown): ExperimentType {
  if (typeof value !== 'string') {
    throw new EngineError('UNSUPPORTED_TYPE', 'An experiment type is required.');
  }
  for (let i = 0; i < SUPPORTED_TYPES.length; i++) {
    if (SUPPORTED_TYPES[i] === value) {
      return SUPPORTED_TYPES[i];
    }
  }
  throw new EngineError('UNSUPPORTED_TYPE', 'That experiment type is not available in this lab.');
}

export function listSupportedTypes(): ExperimentType[] {
  const out: ExperimentType[] = [];
  for (let i = 0; i < SUPPORTED_TYPES.length; i++) {
    out.push(SUPPORTED_TYPES[i]);
  }
  return out;
}
