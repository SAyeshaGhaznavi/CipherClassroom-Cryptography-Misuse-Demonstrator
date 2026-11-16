/**
 * Turns every error into a safe JSON answer:  { "code": "...", "message": "..." }
 * Stack traces and internal details are never sent to the client.
 */
import type { ErrorRequestHandler, RequestHandler } from 'express';
import { EngineError, toSafeError } from 'cipherclassroom-engine';
import type { Repositories } from '../repositories';
import { actorName } from './auth';

/** Throw this in a route to answer with a given status, code and message. */
export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const notFoundHandler: RequestHandler = (_req, res) => {
  res.status(404).json({ code: 'NOT_FOUND', message: 'The requested resource was not found.' });
};

export function createErrorHandler(repos: Repositories): ErrorRequestHandler {
  return (error, req, res, _next) => {
    // 1. Errors we throw on purpose.
    if (error instanceof ApiError) {
      res.status(error.status).json({ code: error.code, message: error.message });
      return;
    }

    // 2. Errors from the security engine already have a safe code and status.
    if (error instanceof EngineError) {
      res.status(error.httpStatus).json(toSafeError(error));
      return;
    }

    // 3. Errors from express.json(): body too large or not valid JSON.
    if (error.type === 'entity.too.large' || error.type === 'entity.parse.failed') {
      let status = 400;
      let code = 'INVALID_INPUT';
      let message = 'The request body is not valid JSON.';
      if (error.type === 'entity.too.large') {
        status = 413;
        code = 'INPUT_TOO_LARGE';
        message = 'The request body is too large.';
      }
      repos.audit.append({
        actor: actorName(req),
        action: 'request.rejected',
        outcome: 'failure',
        severity: 'warning',
        detail: req.method + ' ' + req.path + ' rejected with ' + code + '.'
      });
      res.status(status).json({ code, message });
      return;
    }

    // 4. Anything else is a bug: log it on the server, answer with a generic message.
    console.error(error);
    repos.audit.append({
      actor: actorName(req),
      action: 'server.error',
      outcome: 'failure',
      severity: 'critical',
      detail: 'Unexpected error on ' + req.method + ' ' + req.path + '.'
    });
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Something went wrong. Please try again.' });
  };
}
