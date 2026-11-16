/**
 * Authentication and authorization middleware.
 *
 *   loadSession   reads the session cookie and puts the logged-in user on req.auth
 *   requireLogin  stops the request if nobody is logged in            (401)
 *   requireRole   stops the request if the user's role is not allowed (403)
 *
 * The role always comes from the database, never from the browser.
 */
import type { Request, RequestHandler } from 'express';
import type { Repositories } from '../repositories';
import type { Role } from '../repositories/userRepository';

export const SESSION_COOKIE = 'cc_session';

export interface AuthInfo {
  userId: string;
  username: string;
  role: Role;
  tokenHash: string;
  csrfToken: string;
  expiresAt: string;
}

// Tell TypeScript that Express requests can carry `auth`.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthInfo;
    }
  }
}

/** The logged-in user. Only call this after requireLogin or requireRole. */
export function getAuth(req: Request): AuthInfo {
  if (req.auth === undefined) {
    throw new Error('getAuth() used on a request without a logged-in user.');
  }
  return req.auth;
}

/** The name written to the audit log for this request. */
export function actorName(req: Request): string {
  if (req.auth === undefined) {
    return 'anonymous';
  }
  return req.auth.username;
}

export function loadSession(repos: Repositories): RequestHandler {
  return (req, _res, next) => {
    const token = req.cookies?.[SESSION_COOKIE];
    if (typeof token !== 'string' || token === '') {
      next();
      return;
    }

    const session = repos.sessions.findByToken(token);
    if (session === null) {
      next();
      return;
    }

    const user = repos.users.findById(session.userId);
    if (user === null) {
      next();
      return;
    }

    req.auth = {
      userId: user.id,
      username: user.username,
      role: user.role,
      tokenHash: session.tokenHash,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt
    };
    next();
  };
}

export const requireLogin: RequestHandler = (req, res, next) => {
  if (req.auth === undefined) {
    res.status(401).json({ code: 'UNAUTHENTICATED', message: 'Please sign in.' });
    return;
  }
  next();
};

/**
 * Lets only the given roles through. Anyone else gets a generic denial,
 * and the attempt is written to the audit log.
 */
export function requireRole(repos: Repositories, allowedRoles: Role[]): RequestHandler {
  return (req, res, next) => {
    if (req.auth === undefined) {
      res.status(401).json({ code: 'UNAUTHENTICATED', message: 'Please sign in.' });
      return;
    }

    if (!allowedRoles.includes(req.auth.role)) {
      repos.audit.append({
        actor: req.auth.username,
        action: 'access.denied',
        outcome: 'failure',
        severity: 'warning',
        detail: req.auth.role + ' tried ' + req.method + ' ' + req.originalUrl + '.'
      });
      res.status(403).json({ code: 'FORBIDDEN', message: 'You do not have permission to do this.' });
      return;
    }

    next();
  };
}
