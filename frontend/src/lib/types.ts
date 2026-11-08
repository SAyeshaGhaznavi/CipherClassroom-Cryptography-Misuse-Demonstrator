export type Role = 'operator' | 'admin' | 'viewer';
export type ExperimentType = 'classical-cipher' | 'authenticated-encryption' | 'hashing-kdfs' | 'nonce-reuse' | 'test-vectors' | 'avalanche';
export type Severity = 'info' | 'warning' | 'critical';
export interface ExperimentResult {
  id: string;
  type: ExperimentType;
  title: string;
  timestamp: string;
  status: 'completed' | 'rejected';
  severity: Severity;
  summary: string;
  details: { label: string; value: string }[];
  warnings: string[];
  evidence: { name: string; value: string }[];
  durationMs: number;
  version: string;
}
export interface AuditEvent { id: string; timestamp: string; action: string; actor: string; detail: string; }
export interface User { username: string; role: Role; }
export interface ExperimentInput { type: ExperimentType; text: string; secondary?: string; shift?: number; iterations?: number; mode?: string; }
export type TestResult = {name: string; expected: string; actual: string; passed: boolean};
