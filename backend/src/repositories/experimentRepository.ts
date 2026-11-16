/**
 * Reads and writes the experiments table.
 *
 * The result from the security engine is saved exactly as the engine
 * returned it (see engine/docs/ENGINE_CONTRACT.md). It already contains
 * the rule name, versions, thresholds and reasons needed to reproduce the
 * decision, and no plaintext in its metadata.
 */
import type { EngineResult } from 'cipherclassroom-engine';
import type { Db } from '../database';

/** History is capped so one request can never return an unlimited list. */
const HISTORY_LIMIT = 200;

interface ExperimentRow {
  result_json: string;
}

export class ExperimentRepository {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  save(result: EngineResult, username: string): void {
    this.db
      .prepare('INSERT INTO experiments (id, created_by, created_at, result_json) VALUES (?, ?, ?, ?)')
      .run(result.id, username, result.timestamp, JSON.stringify(result));
  }

  findById(id: string): EngineResult | null {
    const row = this.db.prepare('SELECT result_json FROM experiments WHERE id = ?').get(id) as
      | ExperimentRow
      | undefined;
    if (row === undefined) {
      return null;
    }
    return JSON.parse(row.result_json) as EngineResult;
  }

  /** Newest first. */
  list(): EngineResult[] {
    const rows = this.db
      .prepare('SELECT result_json FROM experiments ORDER BY created_at DESC, rowid DESC LIMIT ?')
      .all(HISTORY_LIMIT) as ExperimentRow[];

    const results: EngineResult[] = [];
    for (const row of rows) {
      results.push(JSON.parse(row.result_json) as EngineResult);
    }
    return results;
  }
}
