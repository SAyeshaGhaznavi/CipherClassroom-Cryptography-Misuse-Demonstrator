/**
 * Authentication endpoints (docs/API_CONTRACT.md).
 *
 *   POST /api/auth/login    public      log in, start a session
 *   POST /api/auth/logout   signed in   end the session
 *   GET  /api/auth/me       signed in   current user, used after a page refresh
 */
import { Router } from 'express';
import type { AppConfig } from '../config';
import { getAuth, requireLogin, SESSION_COOKIE } from '../middleware/auth';
import { requireCsrf } from '../middleware/csrf';
import { ApiError } from '../middleware/errors';
import { createLoginLimiter } from '../middleware/rateLimit';
import type { Repositories } from '../repositories';
import { verifyPassword } from '../security/password';

/** Checks the login body and returns the username and password. */
function readLoginBody(body: unknown): { username: string; password: string } {
  if (typeof body !== 'object' || body === null) {
    throw new ApiError(400, 'INVALID_INPUT', 'Username and password are required.');
  }
  const fields = body as Record<string, unknown>;

  if (typeof fields.username !== 'string' || fields.username.trim() === '' || fields.username.length > 64) {
    throw new ApiError(400, 'INVALID_INPUT', 'Username is required (at most 64 characters).');
  }
  if (typeof fields.password !== 'string' || fields.password === '' || fields.password.length > 256) {
    throw new ApiError(400, 'INVALID_INPUT', 'Password is required (at most 256 characters).');
  }
  // Any other field, such as "role", is ignored. The role comes from the database.
  return { username: fields.username.trim(), password: fields.password };
}

export function createAuthRouter(config: AppConfig, repos: Repositories): Router {
  const router = Router();

  router.post('/login', createLoginLimiter(repos), async (req, res) => {
    const { username, password } = readLoginBody(req.body);
    const user = repos.users.findByUsername(username);

    let passwordOk = false;
    if (user !== null) {
      passwordOk = await verifyPassword(password, user.passwordHash);
    }

    if (user === null || !passwordOk) {
      // The typed username is not logged for unknown accounts: people
      // sometimes type their password into the username field by mistake.
      let actor = 'unknown';
      let detail = 'Login failed: unknown username.';
      if (user !== null) {
        actor = user.username;
        detail = 'Login failed: wrong password.';
      }
      repos.audit.append({ actor, action: 'login.failure', outcome: 'failure', severity: 'warning', detail });
      // Same message in both cases, so nobody can find out which usernames exist.
      throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid username or password.');
    }

    // End any session this browser already had, then start a new one.
    if (req.auth !== undefined) {
      repos.sessions.delete(req.auth.tokenHash);
    }
    const { token, session } = repos.sessions.create(user.id, config.sessionHours);

    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true, // JavaScript in the page cannot read the cookie
      sameSite: 'strict', // the browser does not send it with requests from other sites
      secure: config.cookieSecure, // HTTPS only, when enabled
      path: '/',
      maxAge: config.sessionHours * 60 * 60 * 1000
    });

    repos.audit.append({
      actor: user.username,
      action: 'login.success',
      outcome: 'success',
      severity: 'info',
      detail: user.username + ' logged in as ' + user.role + '.'
    });

    res.json({
      username: user.username,
      role: user.role,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt
    });
  });

  router.post('/logout', requireLogin, requireCsrf(repos), (req, res) => {
    const auth = getAuth(req);
    repos.sessions.delete(auth.tokenHash);
    res.clearCookie(SESSION_COOKIE, { path: '/' });

    repos.audit.append({
      actor: auth.username,
      action: 'logout',
      outcome: 'success',
      severity: 'info',
      detail: auth.username + ' logged out.'
    });
    res.json({ ok: true });
  });

  router.get('/me', requireLogin, (req, res) => {
    const auth = getAuth(req);
    res.json({
      username: auth.username,
      role: auth.role,
      csrfToken: auth.csrfToken,
      expiresAt: auth.expiresAt
    });
  });

  return router;
}
