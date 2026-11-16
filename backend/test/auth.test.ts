import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import request from 'supertest';
import { sha256 } from '../src/security/tokens';
import { auditActions, login, PASSWORDS, setup } from './helpers';

describe('login', () => {
  it('logs in and takes the role from the database, not from the request', async () => {
    const { app, repos } = await setup();
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'operator', password: PASSWORDS.operator, role: 'admin' });

    assert.equal(res.status, 200);
    assert.equal(res.body.username, 'operator');
    assert.equal(res.body.role, 'operator');
    assert.equal(typeof res.body.csrfToken, 'string');
    assert.ok(auditActions(repos).includes('login.success'));
  });

  it('sets an HttpOnly, SameSite=Strict session cookie', async () => {
    const { app } = await setup();
    const res = await request(app).post('/api/auth/login').send({ username: 'viewer', password: PASSWORDS.viewer });
    const cookie = String(res.headers['set-cookie']);

    assert.match(cookie, /cc_session=/);
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);
  });

  it('gives the same answer for a wrong password and an unknown user, and logs both', async () => {
    const { app, repos } = await setup();
    const wrongPassword = await request(app).post('/api/auth/login').send({ username: 'admin', password: 'wrong' });
    const unknownUser = await request(app).post('/api/auth/login').send({ username: 'nobody', password: 'wrong' });

    assert.equal(wrongPassword.status, 401);
    assert.deepEqual(wrongPassword.body, unknownUser.body);
    assert.equal(wrongPassword.body.code, 'INVALID_CREDENTIALS');
    assert.equal(auditActions(repos).filter((action) => action === 'login.failure').length, 2);
  });

  it('does not write the typed username of an unknown account to the audit log', async () => {
    const { app, repos } = await setup();
    await request(app).post('/api/auth/login').send({ username: 'MySecretTypedHere', password: 'x' });
    assert.ok(!JSON.stringify(repos.audit.list()).includes('MySecretTypedHere'));
  });

  it('rejects a login without a password', async () => {
    const { app } = await setup();
    const res = await request(app).post('/api/auth/login').send({ username: 'admin' });
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'INVALID_INPUT');
  });

  it('rate limits repeated failed logins', async () => {
    const { app, repos } = await setup();
    let lastStatus = 0;
    for (let i = 0; i < 11; i++) {
      const res = await request(app).post('/api/auth/login').send({ username: 'admin', password: 'wrong' });
      lastStatus = res.status;
    }
    assert.equal(lastStatus, 429);
    assert.ok(auditActions(repos).includes('rate_limit.exceeded'));
  });
});

describe('stored credentials and sessions', () => {
  it('stores the password only as a scrypt hash and the session token only as a SHA-256 hash', async () => {
    const { app, db } = await setup();
    const res = await request(app).post('/api/auth/login').send({ username: 'admin', password: PASSWORDS.admin });

    const user = db.prepare("SELECT password_hash FROM users WHERE username = 'admin'").get() as { password_hash: string };
    assert.match(user.password_hash, /^scrypt\$/);
    assert.ok(!user.password_hash.includes(PASSWORDS.admin));

    const cookie = String(res.headers['set-cookie']);
    const token = cookie.split(';')[0].split('=')[1];
    const session = db.prepare('SELECT token_hash FROM sessions').get() as { token_hash: string };
    assert.notEqual(session.token_hash, token);
    assert.equal(session.token_hash, sha256(token));
  });

  it('/me returns the logged-in user and needs a session', async () => {
    const { app } = await setup();
    const anonymous = await request(app).get('/api/auth/me');
    assert.equal(anonymous.status, 401);

    const { agent } = await login(app, 'viewer');
    const me = await agent.get('/api/auth/me');
    assert.equal(me.status, 200);
    assert.equal(me.body.role, 'viewer');
  });

  it('logout ends the session on the server', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'operator');

    const out = await agent.post('/api/auth/logout').set('X-CSRF-Token', csrf);
    assert.equal(out.status, 200);
    assert.equal((await agent.get('/api/auth/me')).status, 401);
    assert.ok(auditActions(repos).includes('logout'));
  });

  it('an expired session is no longer accepted', async () => {
    const { app, db } = await setup();
    const { agent } = await login(app, 'operator');
    db.prepare('UPDATE sessions SET expires_at = ?').run(new Date(Date.now() - 1000).toISOString());

    assert.equal((await agent.get('/api/auth/me')).status, 401);
  });
});

describe('CSRF protection', () => {
  it('refuses a change request without the CSRF token and logs it', async () => {
    const { app, repos } = await setup();
    const { agent } = await login(app, 'operator');
    const res = await agent.post('/api/auth/logout');

    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'CSRF_FAILED');
    assert.ok(auditActions(repos).includes('csrf.rejected'));
  });

  it('refuses a wrong CSRF token', async () => {
    const { app } = await setup();
    const { agent } = await login(app, 'operator');
    const res = await agent.post('/api/auth/logout').set('X-CSRF-Token', 'not-the-right-token');
    assert.equal(res.status, 403);
  });

  it('allows the frontend address with cookies (CORS)', async () => {
    const { app } = await setup();
    const res = await request(app)
      .options('/api/auth/login')
      .set('Origin', 'http://localhost:5173')
      .set('Access-Control-Request-Method', 'POST');

    assert.equal(res.headers['access-control-allow-origin'], 'http://localhost:5173');
    assert.equal(res.headers['access-control-allow-credentials'], 'true');
  });
});
