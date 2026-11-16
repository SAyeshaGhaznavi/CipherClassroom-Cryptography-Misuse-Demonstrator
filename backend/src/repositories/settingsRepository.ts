/**
 * Saves the lab policy so it survives a server restart.
 *
 * The engine keeps its policy in memory only. As ENGINE_CONTRACT.md
 * suggests, we store the editable values here after every change, and at
 * startup we call updatePolicy() with the stored values.
 */
import type { Db } from '../database';

const POLICY_KEY = 'lab_policy';

interface SettingRow {
  value: string;
}

export class SettingsRepository {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  savePolicy(values: Record<string, number>): void {
    this.db
      .prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run(POLICY_KEY, JSON.stringify(values));
  }

  /** Returns the saved policy values, or null if the admin never changed anything. */
  loadPolicy(): Record<string, number> | null {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(POLICY_KEY) as SettingRow | undefined;
    if (row === undefined) {
      return null;
    }
    return JSON.parse(row.value) as Record<string, number>;
  }
}
