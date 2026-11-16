/**
 * Opens the SQLite database and creates the tables if they do not exist.
 *
 * Tables:
 *   users          accounts (password stored only as a hash)
 *   sessions       logged-in sessions (cookie token stored only as a hash)
 *   experiments    experiment results returned by the security engine
 *   audit_events   audit log, append-only
 *   settings       saved lab policy, so it survives a restart
 */
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';

export type Db = Database.Database;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    created_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS experiments (
    id          TEXT PRIMARY KEY,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    result_json TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_events (
    id           TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    detail       TEXT NOT NULL,
    result_id    TEXT,
    input_digest TEXT NOT NULL
  );

  -- Append-only: the database itself refuses to change or delete audit events.
  CREATE TRIGGER IF NOT EXISTS audit_events_no_update BEFORE UPDATE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
  CREATE TRIGGER IF NOT EXISTS audit_events_no_delete BEFORE DELETE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`;

/** Pass ':memory:' to get an empty throwaway database (used by the tests). */
export function openDatabase(filePath: string): Db {
  if (filePath !== ':memory:') {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
  }
  const db = new Database(filePath);
  db.pragma('foreign_keys = ON');
  db.exec(SCHEMA);
  return db;
}
