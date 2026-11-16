/**
 * Reads and appends to the audit_events table.
 *
 * The event format is the one from engine/docs/ENGINE_CONTRACT.md
 * (timestamp, action, outcome, severity, detail, resultId, inputDigest)
 * plus the `id` and `actor` fields that the frontend admin page shows.
 *
 * There is no update or delete method, and database triggers block those
 * operations too, so the log is append-only.
 */
import type { AuditEventDraft, Severity } from 'cipherclassroom-engine';
import type { Db } from '../database';
import { newId } from '../security/tokens';

/** How many events the admin page receives at most. */
const AUDIT_LIMIT = 500;

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  outcome: 'success' | 'failure';
  severity: Severity;
  detail: string;
  resultId: string | null;
  inputDigest: string;
}

/** What a caller passes in. timestamp, resultId and inputDigest are optional. */
export interface NewAuditEvent {
  actor: string;
  action: string;
  outcome: 'success' | 'failure';
  severity: Severity;
  detail: string;
  resultId?: string | null;
  inputDigest?: string;
  timestamp?: string;
}

interface AuditRow {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  outcome: 'success' | 'failure';
  severity: Severity;
  detail: string;
  result_id: string | null;
  input_digest: string;
}

export class AuditRepository {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  append(event: NewAuditEvent): void {
    let timestamp = new Date().toISOString();
    if (event.timestamp) {
      timestamp = event.timestamp;
    }

    let resultId: string | null = null;
    if (event.resultId) {
      resultId = event.resultId;
    }

    let inputDigest = '';
    if (event.inputDigest) {
      inputDigest = event.inputDigest;
    }

    this.db
      .prepare(
        `INSERT INTO audit_events
           (id, timestamp, actor, action, outcome, severity, detail, result_id, input_digest)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(newId(), timestamp, event.actor, event.action, event.outcome, event.severity, event.detail, resultId, inputDigest);
  }

  /** Saves an event handed back by the security engine, adding who did it. */
  appendEngineEvent(draft: AuditEventDraft, actor: string): void {
    this.append({
      actor: actor,
      action: draft.action,
      outcome: draft.outcome,
      severity: draft.severity,
      detail: draft.detail,
      resultId: draft.resultId,
      inputDigest: draft.inputDigest,
      timestamp: draft.timestamp
    });
  }

  /** Newest first. */
  list(): AuditEvent[] {
    const rows = this.db
      .prepare('SELECT * FROM audit_events ORDER BY timestamp DESC, rowid DESC LIMIT ?')
      .all(AUDIT_LIMIT) as AuditRow[];

    const events: AuditEvent[] = [];
    for (const row of rows) {
      events.push({
        id: row.id,
        timestamp: row.timestamp,
        actor: row.actor,
        action: row.action,
        outcome: row.outcome,
        severity: row.severity,
        detail: row.detail,
        resultId: row.result_id,
        inputDigest: row.input_digest
      });
    }
    return events;
  }
}
