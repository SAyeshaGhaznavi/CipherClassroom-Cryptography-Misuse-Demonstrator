import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import request from 'supertest';
import { getPolicy } from 'cipherclassroom-engine';
import { auditActions, login, PASSWORDS, setup } from './helpers';

const CAESAR = { type: 'classical-cipher', text: 'HELLO', shift: 3 };

describe('audit log', () => {
  it('admin can read it, with the fields the frontend shows', async () => {
    const { app } = await setup();
    const { agent } = await login(app, 'admin');
    const res = await agent.get('/api/admin/audit');

    assert.equal(res.status, 200);
    const event = res.body[0];
    for (const field of ['id', 'timestamp', 'action', 'actor', 'detail']) {
      assert.ok(field in event, 'event has ' + field);
    }
  });

  it('operator and viewer get a generic denial, and the attempt is logged', async () => {
    const { app, repos } = await setup();
    for (const role of ['operator', 'viewer'] as const) {
      const { agent } = await login(app, role);
      const res = await agent.get('/api/admin/audit');
      assert.equal(res.status, 403);
      assert.equal(res.body.code, 'FORBIDDEN');
    }
    assert.equal(auditActions(repos).filter((action) => action === 'access.denied').length, 2);
  });

  it('is append-only: events cannot be changed or deleted', async () => {
    const { app, db } = await setup();
    await login(app, 'admin');
    assert.throws(() => db.prepare("UPDATE audit_events SET detail = 'changed'").run(), /append-only/);
    assert.throws(() => db.prepare('DELETE FROM audit_events').run(), /append-only/);
  });
});

describe('lab configuration', () => {
  it('needs confirmation', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'admin');
    const res = await agent.patch('/api/admin/config').set('X-CSRF-Token', csrf).send({ minSafeKdfIterations: 200000 });
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'CONFIRMATION_REQUIRED');
  });

  it('applies a permitted change, logs it, and the next result uses the new policy', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'admin');

    const res = await agent
      .patch('/api/admin/config')
      .set('X-CSRF-Token', csrf)
      .send({ minSafeKdfIterations: 200000, confirm: true });
    assert.equal(res.status, 200);
    assert.equal(res.body.minSafeKdfIterations, 200000);
    assert.equal(res.body.policyVersion, 'policy-1.0+1');

    const change = repos.audit.list().find((event) => event.action === 'config.change');
    assert.equal(change?.detail, 'admin changed minSafeKdfIterations from 100000 to 200000');

    // 150 000 iterations was fine before; now it is below the minimum.
    const run = await agent
      .post('/api/experiments')
      .set('X-CSRF-Token', csrf)
      .send({ type: 'hashing-kdfs', text: 'sample passphrase', iterations: 150000 });
    assert.equal(run.body.severity, 'warning');
    assert.equal(run.body.engine.policyVersion, 'policy-1.0+1');
  });

  it('with only "confirm": true it changes nothing and returns the current policy', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'admin');
    const res = await agent.patch('/api/admin/config').set('X-CSRF-Token', csrf).send({ confirm: true });

    assert.equal(res.status, 200);
    assert.equal(res.body.policyVersion, 'policy-1.0');
    assert.equal(res.body.minSafeKdfIterations, 100000);
    assert.ok(!auditActions(repos).includes('config.change'));
  });

  it('refuses a value outside the allowed range', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'admin');
    const res = await agent.patch('/api/admin/config').set('X-CSRF-Token', csrf).send({ maxInputLength: 0, confirm: true });
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'INVALID_PARAMETER');
  });

  it('refuses a field that may not be changed, and logs the refusal', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'admin');
    const res = await agent
      .patch('/api/admin/config')
      .set('X-CSRF-Token', csrf)
      .send({ policyVersion: 'fake', confirm: true });

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'POLICY_VIOLATION');
    assert.ok(auditActions(repos).includes('config.rejected'));
  });

  it('is refused for an operator', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent.patch('/api/admin/config').set('X-CSRF-Token', csrf).send({ maxInputLength: 100, confirm: true });
    assert.equal(res.status, 403);
  });
});

describe('recovery after restart (T-final)', () => {
  it('keeps the policy, the session, the history and the audit log', async () => {
    const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'cipherclassroom-test-'));
    const dbFile = path.join(folder, 'test.db');
    try {
      // Before the restart.
      const first = await setup(dbFile);
      const loginRes = await request(first.app)
        .post('/api/auth/login')
        .send({ username: 'admin', password: PASSWORDS.admin });
      const cookie = String(loginRes.headers['set-cookie']).split(';')[0];
      const csrf = loginRes.body.csrfToken;

      await request(first.app)
        .patch('/api/admin/config')
        .set('Cookie', cookie)
        .set('X-CSRF-Token', csrf)
        .send({ maxInputLength: 500, confirm: true });
      const created = await request(first.app)
        .post('/api/experiments')
        .set('Cookie', cookie)
        .set('X-CSRF-Token', csrf)
        .send(CAESAR);
      first.db.close();

      // "Restart": a new app on the same database file.
      const second = await setup(dbFile);
      assert.equal(getPolicy().maxInputLength, 500);

      // The same session cookie still works, and the history and audit log are still there.
      const found = await request(second.app).get('/api/experiments/' + created.body.id).set('Cookie', cookie);
      assert.equal(found.status, 200);
      assert.ok(auditActions(second.repos).includes('config.change'));
      second.db.close();
    } finally {
      fs.rmSync(folder, { recursive: true, force: true });
    }
  });
});

describe('report export', () => {
  it('exports a sanitized report like the frontend does, and logs the export', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const created = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send(CAESAR);

    const res = await agent.get('/api/reports/' + created.body.id + '/export');
    assert.equal(res.status, 200);
    assert.match(String(res.headers['content-disposition']), /attachment; filename="cipherclassroom-/);
    assert.equal(res.body.notice, 'Sanitized summary only; sensitive experiment values excluded.');

    const labels = res.body.details.map((detail: { label: string }) => detail.label);
    assert.ok(!labels.includes('Ciphertext'));
    assert.ok(!JSON.stringify(res.body).includes('KHOOR'));
    assert.ok(auditActions(repos).includes('report.export'));
  });

  it('answers 404 for an unknown experiment', async () => {
    const { app } = await setup();
    const { agent } = await login(app, 'viewer');
    const res = await agent.get('/api/reports/unknown/export');
    assert.equal(res.status, 404);
  });
});
