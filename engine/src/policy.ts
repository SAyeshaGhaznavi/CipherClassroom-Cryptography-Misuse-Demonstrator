/**
 * Lab policy: the thresholds the engine applies when it decides whether a
 * result is informational, a warning, or critical.
 *
 * Thresholds live here rather than inside the modules so an administrator
 * can change one permitted value, repeat a test, and show that both the new
 * result and the configuration change are traceable.
 */

import { EngineError } from './errors';

export interface LabPolicy {
  policyVersion: string;
  /** Maximum accepted input length in characters. */
  maxInputLength: number;
  /** Below this PBKDF2 iteration count the engine raises a critical finding. */
  criticalKdfIterations: number;
  /** Below this count the engine raises a warning. */
  minSafeKdfIterations: number;
  /** Hard upper bound so a request cannot stall an ordinary laptop. */
  maxKdfIterations: number;
  /** Accepted band for the SHA-256 avalanche measurement, in bits of 256. */
  minAvalancheBits: number;
  maxAvalancheBits: number;
  /** Caesar shifts that perform no encryption at all. */
  ineffectiveCaesarShifts: number[];
  /** Minimum Vigenere keyword length before the engine flags it as weak. */
  minVigenereKeywordLength: number;
}

const DEFAULT_POLICY: LabPolicy = {
  policyVersion: 'policy-1.0',
  maxInputLength: 2000,
  criticalKdfIterations: 10000,
  minSafeKdfIterations: 100000,
  maxKdfIterations: 600000,
  minAvalancheBits: 96,
  maxAvalancheBits: 160,
  ineffectiveCaesarShifts: [0, 26],
  minVigenereKeywordLength: 4
};

let activePolicy: LabPolicy = clonePolicy(DEFAULT_POLICY);

export function clonePolicy(policy: LabPolicy): LabPolicy {
  const shifts: number[] = [];
  for (let i = 0; i < policy.ineffectiveCaesarShifts.length; i++) {
    shifts.push(policy.ineffectiveCaesarShifts[i]);
  }
  return {
    policyVersion: policy.policyVersion,
    maxInputLength: policy.maxInputLength,
    criticalKdfIterations: policy.criticalKdfIterations,
    minSafeKdfIterations: policy.minSafeKdfIterations,
    maxKdfIterations: policy.maxKdfIterations,
    minAvalancheBits: policy.minAvalancheBits,
    maxAvalancheBits: policy.maxAvalancheBits,
    ineffectiveCaesarShifts: shifts,
    minVigenereKeywordLength: policy.minVigenereKeywordLength
  };
}

export function getPolicy(): LabPolicy {
  return clonePolicy(activePolicy);
}

export function getDefaultPolicy(): LabPolicy {
  return clonePolicy(DEFAULT_POLICY);
}

export function resetPolicy(): LabPolicy {
  activePolicy = clonePolicy(DEFAULT_POLICY);
  return getPolicy();
}

export interface PolicyChange {
  field: string;
  from: string;
  to: string;
}

export interface PolicyUpdateResult {
  policy: LabPolicy;
  changes: PolicyChange[];
}

/** Numeric fields an administrator is permitted to change, with safe bounds. */
const EDITABLE_FIELDS: Array<{ name: string; min: number; max: number }> = [
  { name: 'maxInputLength', min: 1, max: 10000 },
  { name: 'criticalKdfIterations', min: 1, max: 600000 },
  { name: 'minSafeKdfIterations', min: 1, max: 600000 },
  { name: 'maxKdfIterations', min: 1000, max: 2000000 },
  { name: 'minAvalancheBits', min: 0, max: 256 },
  { name: 'maxAvalancheBits', min: 0, max: 256 },
  { name: 'minVigenereKeywordLength', min: 1, max: 64 }
];

/**
 * Applies an administrator configuration change and returns the list of
 * changed fields so the caller can write one audit event per change.
 */
export function updatePolicy(patch: Record<string, unknown>): PolicyUpdateResult {
  const next = clonePolicy(activePolicy);
  const changes: PolicyChange[] = [];
  const keys = Object.keys(patch);

  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    let field: { name: string; min: number; max: number } | null = null;
    for (let j = 0; j < EDITABLE_FIELDS.length; j++) {
      if (EDITABLE_FIELDS[j].name === key) {
        field = EDITABLE_FIELDS[j];
        break;
      }
    }
    if (field === null) {
      throw new EngineError('POLICY_VIOLATION', 'Field "' + key + '" is not an editable lab policy value.');
    }
    const value = patch[key];
    if (typeof value !== 'number' || !Number.isInteger(value)) {
      throw new EngineError('INVALID_PARAMETER', 'Policy field "' + key + '" must be a whole number.');
    }
    if (value < field.min || value > field.max) {
      throw new EngineError(
        'INVALID_PARAMETER',
        'Policy field "' + key + '" must be between ' + field.min + ' and ' + field.max + '.'
      );
    }
    const record = next as unknown as Record<string, number>;
    const previousValue = record[key];
    if (previousValue !== value) {
      changes.push({ field: key, from: String(previousValue), to: String(value) });
      record[key] = value;
    }
  }

  if (next.criticalKdfIterations > next.minSafeKdfIterations) {
    throw new EngineError(
      'POLICY_VIOLATION',
      'criticalKdfIterations cannot be greater than minSafeKdfIterations.'
    );
  }
  if (next.minAvalancheBits > next.maxAvalancheBits) {
    throw new EngineError('POLICY_VIOLATION', 'minAvalancheBits cannot be greater than maxAvalancheBits.');
  }

  if (changes.length > 0) {
    const parts = next.policyVersion.split('+');
    let revision = 0;
    if (parts.length > 1) {
      revision = Number(parts[1]);
    }
    next.policyVersion = parts[0] + '+' + String(revision + 1);
  }

  activePolicy = next;
  return { policy: getPolicy(), changes: changes };
}
