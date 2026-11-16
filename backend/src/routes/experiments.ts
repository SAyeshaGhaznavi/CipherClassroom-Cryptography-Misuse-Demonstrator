/**
 * Experiment endpoints (docs/API_CONTRACT.md).
 *
 *   POST /api/experiments       operator, admin   validate and run an experiment
 *   GET  /api/experiments       signed in         experiment history
 *   GET  /api/experiments/:id   signed in         one experiment
 */
import { Router } from 'express';
import { EngineError, runExperiment, toSafeError } from 'cipherclassroom-engine';
import type { ExperimentInput, ExperimentType } from 'cipherclassroom-engine';
import { getAuth, requireLogin, requireRole } from '../middleware/auth';
import { requireCsrf } from '../middleware/csrf';
import { ApiError } from '../middleware/errors';
import { createActionLimiter } from '../middleware/rateLimit';
import type { Repositories } from '../repositories';

/**
 * Checks that each field has the right type and copies only the known
 * fields. The engine then checks the values themselves (supported type,
 * shift range, length limit, ...) and answers with its own error codes.
 */
function readExperimentInput(body: unknown): ExperimentInput {
  if (typeof body !== 'object' || body === null) {
    throw new ApiError(400, 'INVALID_INPUT', 'The request body must be a JSON object.');
  }
  const fields = body as Record<string, unknown>;

  if (typeof fields.type !== 'string') {
    throw new ApiError(400, 'INVALID_INPUT', 'Field "type" must be text.');
  }
  if (typeof fields.text !== 'string') {
    throw new ApiError(400, 'INVALID_INPUT', 'Field "text" must be text.');
  }

  const input: ExperimentInput = {
    type: fields.type as ExperimentType,
    text: fields.text
  };

  if (fields.secondary !== undefined) {
    if (typeof fields.secondary !== 'string') {
      throw new ApiError(400, 'INVALID_INPUT', 'Field "secondary" must be text.');
    }
    input.secondary = fields.secondary;
  }
  if (fields.shift !== undefined) {
    if (typeof fields.shift !== 'number') {
      throw new ApiError(400, 'INVALID_INPUT', 'Field "shift" must be a number.');
    }
    input.shift = fields.shift;
  }
  if (fields.iterations !== undefined) {
    if (typeof fields.iterations !== 'number') {
      throw new ApiError(400, 'INVALID_INPUT', 'Field "iterations" must be a number.');
    }
    input.iterations = fields.iterations;
  }
  if (fields.mode !== undefined) {
    if (typeof fields.mode !== 'string') {
      throw new ApiError(400, 'INVALID_INPUT', 'Field "mode" must be text.');
    }
    input.mode = fields.mode;
  }

  return input;
}

export function createExperimentRouter(repos: Repositories): Router {
  const router = Router();

  router.post('/', requireRole(repos, ['operator', 'admin']), requireCsrf(repos), createActionLimiter(repos), async (req, res) => {
    const username = getAuth(req).username;

    let input: ExperimentInput;
    try {
      input = readExperimentInput(req.body);
    } catch (error) {
      repos.audit.append({
        actor: username,
        action: 'experiment.rejected',
        outcome: 'failure',
        severity: 'warning',
        detail: username + ' sent an experiment request with invalid fields.'
      });
      throw error;
    }

    // As shown in engine/docs/ENGINE_CONTRACT.md.
    try {
      const result = await runExperiment(input, {
        actor: username,
        onAuditEvent: (event) => repos.audit.appendEngineEvent(event, username)
      });
      repos.experiments.save(result, username);
      res.json(result);
    } catch (error) {
      const safe = toSafeError(error);
      let status = 400;
      if (error instanceof EngineError) {
        status = error.httpStatus;
      }
      res.status(status).json(safe);
    }
  });

  router.get('/', requireLogin, (_req, res) => {
    res.json(repos.experiments.list());
  });

  router.get('/:id', requireLogin, (req, res) => {
    const result = repos.experiments.findById(String(req.params.id));
    if (result === null) {
      throw new ApiError(404, 'NOT_FOUND', 'Experiment not found.');
    }
    res.json(result);
  });

  return router;
}
