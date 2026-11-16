/**
 * Builds the Express app.
 *
 * It is separate from server.ts so the tests can build an app with their
 * own empty database.
 */
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { type Express } from 'express';
import type { AppConfig } from './config';
import type { Db } from './database';
import { loadSession } from './middleware/auth';
import { createErrorHandler, notFoundHandler } from './middleware/errors';
import { requestLogger } from './middleware/logger';
import { restoreSavedPolicy } from './policy';
import { createRepositories, type Repositories } from './repositories';
import { createAdminRouter } from './routes/admin';
import { createAuthRouter } from './routes/auth';
import { createExperimentRouter } from './routes/experiments';
import { createReportRouter } from './routes/reports';

export function createApp(config: AppConfig, db: Db): { app: Express; repos: Repositories } {
  const repos = createRepositories(db);

  // Bring back the lab policy the administrator saved before the last restart.
  restoreSavedPolicy(repos);

  const app = express();
  app.disable('x-powered-by');

  if (config.logRequests) {
    app.use(requestLogger);
  }

  // Only the frontend addresses from the config may call the API with cookies.
  app.use(cors({ origin: config.corsOrigins, credentials: true }));
  app.use(cookieParser());
  app.use(loadSession(repos));
  // Request bodies must be JSON and at most 16 kB.
  app.use(express.json({ limit: '16kb' }));

  // Opening http://localhost:3001/api in a browser shows that the server is up
  // and which endpoints exist (the list from docs/API_CONTRACT.md).
  app.get('/api', (_req, res) => {
    res.json({
      name: 'CipherClassroom API',
      status: 'running',
      endpoints: [
        'POST  /api/auth/login',
        'POST  /api/auth/logout',
        'GET   /api/auth/me',
        'POST  /api/experiments',
        'GET   /api/experiments',
        'GET   /api/experiments/:id',
        'GET   /api/admin/audit',
        'PATCH /api/admin/config',
        'GET   /api/reports/:id/export'
      ]
    });
  });

  app.use('/api/auth', createAuthRouter(config, repos));
  app.use('/api/experiments', createExperimentRouter(repos));
  app.use('/api/reports', createReportRouter(repos));
  app.use('/api/admin', createAdminRouter(repos));

  app.use(notFoundHandler);
  app.use(createErrorHandler(repos));

  return { app, repos };
}
