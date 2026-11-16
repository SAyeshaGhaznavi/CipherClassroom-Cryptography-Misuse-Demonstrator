/**
 * Replays the requests the frontend (frontend/src/lib/api.ts) makes from the
 * browser at http://localhost:5173, to check that the backend is ready for it:
 * CORS headers, the session cookie, the CSRF header and the JSON shapes that
 * the frontend screens read.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import request from 'supertest';
import { PASSWORDS, setup } from './helpers';

const FRONTEND = 'http://localhost:5173';

describe('requests from the frontend in the browser', () => {
  it('the browser preflight for a JSON request with the CSRF header is allowed', async () => {
    const { app } = await setup();
    const res = await request(app)
      .options('/api/experiments')
      .set('Origin', FRONTEND)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'content-type,x-csrf-token');

    assert.equal(res.status, 204);
    assert.equal(res.headers['access-control-allow-origin'], FRONTEND);
    assert.equal(res.headers['access-control-allow-credentials'], 'true');
    assert.match(String(res.headers['access-control-allow-headers']), /x-csrf-token/i);
  });

  it('a page from another address does not get CORS permission', async () => {
    const { app } = await setup();
    const res = await request(app).get('/api/experiments').set('Origin', 'http://evil.example');
    assert.equal(res.headers['access-control-allow-origin'], undefined);
  });

  it('full flow: login, run, history, audit log, logout', async () => {
    const { app } = await setup();
    const browser = request.agent(app);

    // api.login() -> the frontend reads { username, role }.
    const login = await browser
      .post('/api/auth/login')
      .set('Origin', FRONTEND)
      .send({ username: 'admin', password: PASSWORDS.admin });
    assert.equal(login.status, 200);
    assert.equal(login.headers['access-control-allow-origin'], FRONTEND);
    assert.equal(login.body.username, 'admin');
    assert.equal(login.body.role, 'admin');
    const csrf = login.body.csrfToken;

    // After a page refresh: GET /auth/me brings the user back.
    const me = await browser.get('/api/auth/me').set('Origin', FRONTEND);
    assert.equal(me.body.role, 'admin');

    // api.run() -> the exact body ExperimentDetail sends.
    const run = await browser
      .post('/api/experiments')
      .set('Origin', FRONTEND)
      .set('X-CSRF-Token', csrf)
      .send({ type: 'classical-cipher', text: 'HELLO', secondary: '', shift: 3, iterations: 100000 });
    assert.equal(run.status, 200);
    assert.equal(run.body.status, 'completed');

    // api.history() -> an array of ExperimentResult.
    const history = await browser.get('/api/experiments').set('Origin', FRONTEND);
    assert.ok(Array.isArray(history.body));
    assert.equal(history.body[0].id, run.body.id);

    // api.audits() -> the Admin page shows id, timestamp, action, actor, detail.
    const audits = await browser.get('/api/admin/audit').set('Origin', FRONTEND);
    assert.ok(Array.isArray(audits.body));
    const runEvent = audits.body.find((event: { action: string }) => event.action === 'experiment.run');
    assert.equal(runEvent.actor, 'admin');
    assert.equal(typeof runEvent.id, 'string');
    assert.equal(typeof runEvent.detail, 'string');

    // Logout ends the session.
    const logout = await browser.post('/api/auth/logout').set('Origin', FRONTEND).set('X-CSRF-Token', csrf);
    assert.equal(logout.status, 200);
    assert.equal((await browser.get('/api/auth/me').set('Origin', FRONTEND)).status, 401);
  });

  it('errors have a "message" the frontend can show (api.ts reads data.message)', async () => {
    const { app } = await setup();
    const res = await request(app)
      .post('/api/auth/login')
      .set('Origin', FRONTEND)
      .send({ username: 'admin', password: 'wrong' });
    assert.equal(typeof res.body.message, 'string');
  });

  it('the login body the frontend sends today (no password) gets a clear error', async () => {
    const { app } = await setup();
    const res = await request(app)
      .post('/api/auth/login')
      .set('Origin', FRONTEND)
      .send({ username: 'admin', role: 'admin' });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /Password is required/);
  });
});
