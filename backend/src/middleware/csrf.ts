/**
 * CSRF protection for cookie sessions.
 *
 * Every session has its own random CSRF token. The frontend receives it from
 * POST /api/auth/login (and GET /api/auth/me) and must send it back in the
 * "X-CSRF-Token" header on every request that changes something.
 * Another website cannot read this token, so it cannot fake such a request.
 */
import type { RequestHandler } from 'express';
import type { Repositories } from '../repositories';
import { safeEqual } from '../security/tokens';

export function requireCsrf(repos: Repositories): RequestHandler {
  return (req, res, next) => {
    if (req.auth === undefined) {
      res.status(401).json({ code: 'UNAUTHENTICATED', message: 'Please sign in.' });
      return;
    }

    const sentToken = req.get('X-CSRF-Token');
    if (sentToken !== undefined && safeEqual(sentToken, req.auth.csrfToken)) {
      next();
      return;
    }

    repos.audit.append({
      actor: req.auth.username,
      action: 'csrf.rejected',
      outcome: 'failure',
      severity: 'warning',
      detail: req.method + ' ' + req.originalUrl + ' was sent without a valid CSRF token.'
    });
    res.status(403).json({ code: 'CSRF_FAILED', message: 'The request could not be verified. Please reload the page.' });
  };
}
