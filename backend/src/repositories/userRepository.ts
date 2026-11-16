/**
 * Reads and writes the users table.
 * All SQL uses "?" placeholders, so user input can never change the query.
 */
import type { Db } from '../database';
import { newId } from '../security/tokens';

export type Role = 'admin' | 'operator' | 'viewer';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: Role;
}

interface UserRow {
  id: string;
  username: string;
  password_hash: string;
  role: Role;
}

function toUser(row: UserRow): User {
  return {
    id: row.id,
    username: row.username,
    passwordHash: row.password_hash,
    role: row.role
  };
}

export class UserRepository {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  create(username: string, passwordHash: string, role: Role): User {
    const id = newId();
    this.db
      .prepare('INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, username, passwordHash, role, new Date().toISOString());
    return { id, username, passwordHash, role };
  }

  findById(id: string): User | null {
    const row = this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    if (row === undefined) {
      return null;
    }
    return toUser(row);
  }

  findByUsername(username: string): User | null {
    const row = this.db.prepare('SELECT * FROM users WHERE username = ?').get(username) as UserRow | undefined;
    if (row === undefined) {
      return null;
    }
    return toUser(row);
  }

  setPasswordHash(id: string, passwordHash: string): void {
    this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, id);
  }
}
