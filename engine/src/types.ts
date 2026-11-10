/**
 * Shared result and input contract for the CipherClassroom security engine.
 *
 * ExperimentResult is intentionally identical to the shape documented in
 * docs/API_CONTRACT.md and used by frontend/src/lib/types.ts, so a result
 * produced here can be returned by the API and rendered by the frontend
 * without any field mapping.
 */

export type ExperimentType =
  | 'classical-cipher'
  | 'authenticated-encryption'
  | 'hashing-kdfs'
  | 'nonce-reuse'
  | 'test-vectors'
  | 'avalanche';

export type Severity = 'info' | 'warning' | 'critical';

export type ResultStatus = 'completed' | 'rejected';

export interface DetailItem {
  label: string;
  value: string;
}

export interface EvidenceItem {
  name: string;
  value: string;
}

/** The exact object the API returns and the frontend renders. */
export interface ExperimentResult {
  id: string;
  type: ExperimentType;
  title: string;
  timestamp: string;
  status: ResultStatus;
  severity: Severity;
  summary: string;
  details: DetailItem[];
  warnings: string[];
  evidence: EvidenceItem[];
  durationMs: number;
  version: string;
}

/**
 * Reproducibility metadata. The specification requires that rule names,
 * version details, thresholds and reasons are stored with every result so a
 * reviewer can reproduce the decision later.
 */
export interface EngineMetadata {
  ruleName: string;
  engineVersion: string;
  policyVersion: string;
  algorithm: string;
  thresholds: Record<string, string>;
  reasons: string[];
  /**
   * First 16 hex characters of the SHA-256 digest of the normalized input.
   * This ties a stored result to the input that produced it without keeping
   * the plaintext itself in the audit record.
   */
  inputDigest: string;
}

/** Superset of ExperimentResult. Extra data lives under `engine` only. */
export interface EngineResult extends ExperimentResult {
  engine: EngineMetadata;
}

/**
 * Input accepted by the engine. Field names match
 * frontend/src/lib/types.ts exactly, so no new request fields are needed.
 *
 *  text       primary message
 *  secondary  second message (nonce reuse) or keyword (Vigenere)
 *  shift      Caesar shift, 0 to 25
 *  iterations PBKDF2 iteration count
 *  mode       module variant, for example 'caesar' or 'vigenere'
 */
export interface ExperimentInput {
  type: ExperimentType;
  text: string;
  secondary?: string;
  shift?: number;
  iterations?: number;
  mode?: string;
}

export interface TestResult {
  name: string;
  expected: string;
  actual: string;
  passed: boolean;
}

/**
 * An audit event the engine suggests. The engine does not own storage.
 * Member A's repository layer appends these to the audit log.
 */
export interface AuditEventDraft {
  timestamp: string;
  action: string;
  outcome: 'success' | 'failure';
  severity: Severity;
  detail: string;
  resultId: string | null;
  inputDigest: string;
}

export interface EngineOptions {
  /** Optional hook so the API layer can append suggested audit events. */
  onAuditEvent?: (event: AuditEventDraft) => void;
  /** Identifier of the signed in user, used only in audit detail text. */
  actor?: string;
}
