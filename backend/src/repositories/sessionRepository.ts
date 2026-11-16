/**
 * Reads and writes the sessions table.
 *
 * On login a random token is created and sent to the browser in a cookie.
 * Only the SHA-256 hash of the token is saved here, so somebody who copies
 * the database still cannot use the sessions.
 */
import type { Db } from '../database';
import { newToken, sha256 } from '../security/tokens';

export interface Session {
  tokenHash: string;
  userId: string;
  csrfToken: string;
  expiresAt: string;
}

interface SessionRow {
  token_hash: string;
  user_id: string;
  csrf_token: string;
  expires_at: string;
}

export class SessionRepository {
  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  /** Creates a session and returns the raw token (for the cookie) together with the session. */
  create(userId: string, hours: number): { token: string; session: Session } {
    const token = newToken();
    const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
    const session: Session = {
      tokenHash: sha256(token),
      userId: userId,
      csrfToken: newToken(),
      expiresAt: expiresAt
    };

    this.db
      .prepare('INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)')
      .run(session.tokenHash, session.userId, session.csrfToken, session.expiresAt);

    return { token, session };
  }

  /** Returns the session for a cookie token, or null if it does not exist or has expired. */
  findByToken(token: string): Session | null {
    const tokenHash = sha256(token);
    const row = this.db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash) as
      | SessionRow
      | undefined;
    if (row === undefined) {
      return null;
    }

    const expired = new Date(row.expires_at).getTime() <= Date.now();
    if (expired) {
      this.delete(tokenHash);
      return null;
    }

    return {
      tokenHash: row.token_hash,
      userId: row.user_id,
      csrfToken: row.csrf_token,
      expiresAt: row.expires_at
    };
  }

  delete(tokenHash: string): void {
    this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
  }

  deleteAllForUser(userId: string): void {
    this.db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  }
}
