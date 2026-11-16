import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import request from 'supertest';
import { auditActions, login, setup } from './helpers';

const CAESAR = { type: 'classical-cipher', text: 'HELLO', shift: 3 };

describe('running an experiment', () => {
  it('operator runs an experiment and gets the ExperimentResult from the API contract', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send(CAESAR);

    assert.equal(res.status, 200);
    const fields = ['id', 'type', 'title', 'timestamp', 'status', 'severity', 'summary', 'details', 'warnings', 'evidence', 'durationMs', 'version'];
    for (const field of fields) {
      assert.ok(field in res.body, 'result has ' + field);
    }
    // Rule name, versions, thresholds and reasons are kept so the decision can be reproduced.
    assert.equal(typeof res.body.engine.ruleName, 'string');
    assert.ok(repos.experiments.findById(res.body.id) !== null);

    const runEvent = repos.audit.list().find((event) => event.action === 'experiment.run');
    assert.equal(runEvent?.actor, 'operator');
  });

  it('accepts the exact request body the frontend sends', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'admin');
    const res = await agent
      .post('/api/experiments')
      .set('X-CSRF-Token', csrf)
      .send({ type: 'authenticated-encryption', text: 'attack at dawn', secondary: '', shift: 3, iterations: 100000 });
    assert.equal(res.status, 200);
  });

  it('a viewer gets a generic denial and the attempt is logged', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'viewer');
    const res = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send(CAESAR);

    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'FORBIDDEN');
    assert.ok(auditActions(repos).includes('access.denied'));
  });

  it('a request without login is refused', async () => {
    const { app } = await setup();
    const res = await request(app).post('/api/experiments').send(CAESAR);
    assert.equal(res.status, 401);
  });

  it('a request without the CSRF token is refused', async () => {
    const { app } = await setup();
    const { agent } = await login(app, 'operator');
    const res = await agent.post('/api/experiments').send(CAESAR);
    assert.equal(res.status, 403);
    assert.equal(res.body.code, 'CSRF_FAILED');
  });
});

describe('invalid input (T-final)', () => {
  it('passes the engine error code through, saves nothing and logs the rejection', async () => {
    const { app, repos } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send({ ...CAESAR, shift: 30 });

    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'INVALID_PARAMETER');
    assert.equal(repos.experiments.list().length, 0);
    assert.ok(auditActions(repos).includes('experiment.rejected'));
  });

  it('refuses a field with the wrong type', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send({ type: 'classical-cipher', text: 42 });
    assert.equal(res.status, 400);
    assert.equal(res.body.code, 'INVALID_INPUT');
  });

  it('refuses an unsupported experiment type', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send({ type: 'unknown', text: 'HELLO' });
    assert.equal(res.status, 422);
    assert.equal(res.body.code, 'UNSUPPORTED_TYPE');
  });

  it('refuses text longer than the lab policy allows', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent
      .post('/api/experiments')
      .set('X-CSRF-Token', csrf)
      .send({ type: 'authenticated-encryption', text: 'A'.repeat(2001) });
    assert.equal(res.status, 413);
    assert.equal(res.body.code, 'INPUT_TOO_LARGE');
  });

  it('refuses an oversized request body', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent
      .post('/api/experiments')
      .set('X-CSRF-Token', csrf)
      .send({ type: 'authenticated-encryption', text: 'A'.repeat(20000) });
    assert.equal(res.status, 413);
    assert.equal(res.body.code, 'INPUT_TOO_LARGE');
  });

  it('answers malformed JSON with a safe error and no stack trace', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const res = await agent
      .post('/api/experiments')
      .set('X-CSRF-Token', csrf)
      .set('Content-Type', 'application/json')
      .send('{"type": "classical-cipher",');

    assert.equal(res.status, 400);
    assert.deepEqual(Object.keys(res.body).sort(), ['code', 'message']);
    assert.ok(!res.text.includes(' at '));
  });
});

describe('repeated submission (T-final)', () => {
  it('every submission gets its own server-generated id', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const first = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send(CAESAR);
    const second = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send(CAESAR);
    assert.notEqual(first.body.id, second.body.id);
  });

  it('too many submissions in a minute are rate limited', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    let lastStatus = 0;
    for (let i = 0; i < 31; i++) {
      const res = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send(CAESAR);
      lastStatus = res.status;
    }
    assert.equal(lastStatus, 429);
  });
});

describe('history', () => {
  it('every signed-in role can read the history, newest first', async () => {
    const { app } = await setup();
    const operator = await login(app, 'operator');
    await operator.agent.post('/api/experiments').set('X-CSRF-Token', operator.csrf).send(CAESAR);
    await operator.agent
      .post('/api/experiments')
      .set('X-CSRF-Token', operator.csrf)
      .send({ type: 'authenticated-encryption', text: 'hello' });

    const viewer = await login(app, 'viewer');
    const res = await viewer.agent.get('/api/experiments');
    assert.equal(res.status, 200);
    assert.equal(res.body.length, 2);
    assert.equal(res.body[0].type, 'authenticated-encryption');
  });

  it('returns one experiment by id, and 404 for an unknown id', async () => {
    const { app } = await setup();
    const { agent, csrf } = await login(app, 'operator');
    const created = await agent.post('/api/experiments').set('X-CSRF-Token', csrf).send(CAESAR);

    const found = await agent.get('/api/experiments/' + created.body.id);
    assert.equal(found.status, 200);
    assert.equal(found.body.id, created.body.id);

    const missing = await agent.get('/api/experiments/does-not-exist');
    assert.equal(missing.status, 404);
  });

  it('needs a login', async () => {
    const { app } = await setup();
    const res = await request(app).get('/api/experiments');
    assert.equal(res.status, 401);
  });
});
