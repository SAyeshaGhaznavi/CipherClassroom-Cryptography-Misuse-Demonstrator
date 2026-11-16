/**
 * Rate limiting on sensitive actions.
 *
 *   login    10 failed logins per 15 minutes from the same address
 *   actions  30 requests per minute per user, for running experiments,
 *            changing the configuration and exporting reports
 */
import type { Request, RequestHandler } from 'express';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import type { Repositories } from '../repositories';
import { actorName } from './auth';

function limitReachedHandler(repos: Repositories): RequestHandler {
  return (req, res) => {
    repos.audit.append({
      actor: actorName(req),
      action: 'rate_limit.exceeded',
      outcome: 'failure',
      severity: 'warning',
      detail: 'Too many requests to ' + req.method + ' ' + req.originalUrl + '.'
    });
    res.status(429).json({ code: 'RATE_LIMITED', message: 'Too many requests. Please wait and try again.' });
  };
}

/** Counts per IP address, because nobody is logged in yet. Successful logins are not counted. */
export function createLoginLimiter(repos: Repositories): RequestHandler {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    skipSuccessfulRequests: true,
    keyGenerator: (req: Request) => ipKeyGenerator(req.ip || ''),
    handler: limitReachedHandler(repos)
  });
}

/** Counts per logged-in user. */
export function createActionLimiter(repos: Repositories): RequestHandler {
  return rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
    keyGenerator: (req: Request) => actorName(req),
    handler: limitReachedHandler(repos)
  });
}
