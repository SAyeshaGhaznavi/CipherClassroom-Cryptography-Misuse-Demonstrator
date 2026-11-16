/**
 * Administrator endpoints (docs/API_CONTRACT.md).
 *
 *   GET   /api/admin/audit    admin   view the append-only audit events
 *   PATCH /api/admin/config   admin   change a permitted lab policy value
 *
 * Changing the configuration is a high-impact action, so the body must
 * include  "confirm": true  (project requirements: "High-impact actions
 * require authorization and confirmation").
 */
import { Router } from 'express';
import { toSafeError, updatePolicy } from 'cipherclassroom-engine';
import { getAuth, requireRole } from '../middleware/auth';
import { requireCsrf } from '../middleware/csrf';
import { ApiError } from '../middleware/errors';
import { createActionLimiter } from '../middleware/rateLimit';
import { saveCurrentPolicy } from '../policy';
import type { Repositories } from '../repositories';

export function createAdminRouter(repos: Repositories): Router {
  const router = Router();
  const adminOnly = requireRole(repos, ['admin']);

  router.get('/audit', adminOnly, (req, res) => {
    const username = getAuth(req).username;
    repos.audit.append({
      actor: username,
      action: 'audit.view',
      outcome: 'success',
      severity: 'info',
      detail: username + ' viewed the audit log.'
    });
    res.json(repos.audit.list());
  });

  router.patch('/config', adminOnly, requireCsrf(repos), createActionLimiter(repos), (req, res) => {
    const username = getAuth(req).username;
    const body = req.body as Record<string, unknown> | undefined;

    if (typeof body !== 'object' || body === null) {
      throw new ApiError(400, 'INVALID_INPUT', 'The request body must be a JSON object.');
    }
    if (body.confirm !== true) {
      throw new ApiError(400, 'CONFIRMATION_REQUIRED', 'Please confirm this change by sending "confirm": true.');
    }

    // Everything except "confirm" is a policy value to change.
    const patch: Record<string, unknown> = {};
    for (const key of Object.keys(body)) {
      if (key !== 'confirm') {
        patch[key] = body[key];
      }
    }

    // As shown in engine/docs/ENGINE_CONTRACT.md.
    try {
      const outcome = updatePolicy(patch);
      for (const change of outcome.changes) {
        repos.audit.append({
          actor: username,
          action: 'config.change',
          outcome: 'success',
          severity: 'warning',
          detail: username + ' changed ' + change.field + ' from ' + change.from + ' to ' + change.to
        });
      }
      saveCurrentPolicy(repos);
      res.json(outcome.policy);
    } catch (error) {
      const safe = toSafeError(error);
      repos.audit.append({
        actor: username,
        action: 'config.rejected',
        outcome: 'failure',
        severity: 'warning',
        detail: username + ' tried a configuration change that was refused: ' + safe.message
      });
      res.status(400).json(safe);
    }
  });

  return router;
}
