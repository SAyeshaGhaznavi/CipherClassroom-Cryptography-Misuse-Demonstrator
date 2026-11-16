/**
 * Report export endpoint (docs/API_CONTRACT.md).
 *
 *   GET /api/reports/:id/export   signed in   download a sanitized report
 *
 * The report has the same shape and the same sanitizing rule as the
 * frontend's "Export sanitized JSON" button (downloadReport in App.tsx):
 * detail rows about plaintext, ciphertext, digests, PBKDF2, salts and XOR
 * values are left out.
 */
import { Router } from 'express';
import type { ExperimentResult } from 'cipherclassroom-engine';
import { getAuth, requireLogin } from '../middleware/auth';
import { ApiError } from '../middleware/errors';
import { createActionLimiter } from '../middleware/rateLimit';
import type { Repositories } from '../repositories';

const SENSITIVE_LABEL = /(plaintext|ciphertext|digest|pbkdf2|salt|xor)/i;

function buildSanitizedReport(result: ExperimentResult) {
  const safeDetails = [];
  for (const detail of result.details) {
    if (!SENSITIVE_LABEL.test(detail.label)) {
      safeDetails.push(detail);
    }
  }

  return {
    id: result.id,
    type: result.type,
    title: result.title,
    timestamp: result.timestamp,
    status: result.status,
    severity: result.severity,
    summary: result.summary,
    details: safeDetails,
    warnings: result.warnings,
    evidence: result.evidence,
    durationMs: result.durationMs,
    version: result.version,
    notice: 'Sanitized summary only; sensitive experiment values excluded.'
  };
}

export function createReportRouter(repos: Repositories): Router {
  const router = Router();

  router.get('/:id/export', requireLogin, createActionLimiter(repos), (req, res) => {
    const result = repos.experiments.findById(String(req.params.id));
    if (result === null) {
      throw new ApiError(404, 'NOT_FOUND', 'Experiment not found.');
    }

    const username = getAuth(req).username;
    repos.audit.append({
      actor: username,
      action: 'report.export',
      outcome: 'success',
      severity: 'info',
      detail: 'Experiment ' + result.id + '; sanitized report',
      resultId: result.id
    });

    const fileName = 'cipherclassroom-' + result.id.slice(0, 8) + '.json';
    res.setHeader('Content-Disposition', 'attachment; filename="' + fileName + '"');
    res.json(buildSanitizedReport(result));
  });

  return router;
}
