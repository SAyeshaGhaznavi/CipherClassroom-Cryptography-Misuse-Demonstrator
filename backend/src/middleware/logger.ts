/**
 * Prints one line per request in the terminal, for example:
 *   POST /api/auth/login 200 95ms
 *
 * Only the method, path, status and time are printed. Request bodies and
 * query strings are never printed, so passwords and inputs stay out of the log.
 */
import type { RequestHandler } from 'express';

export const requestLogger: RequestHandler = (req, res, next) => {
  const startedAt = Date.now();
  res.on('finish', () => {
    const path = req.originalUrl.split('?')[0];
    const ms = Date.now() - startedAt;
    console.log(req.method + ' ' + path + ' ' + res.statusCode + ' ' + ms + 'ms');
  });
  next();
};
