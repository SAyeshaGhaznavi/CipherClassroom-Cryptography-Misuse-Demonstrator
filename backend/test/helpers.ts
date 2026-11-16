/**
 * Shared test setup: a fresh app with its own database and three accounts.
 */
import request from 'supertest';
import type { Express } from 'express';
import { createApp } from '../src/app';
import { loadConfig } from '../src/config';
import { openDatabase, type Db } from '../src/database';
import type { Repositories } from '../src/repositories';
import type { Role } from '../src/repositories/userRepository';
import { hashPassword } from '../src/security/password';

export const PASSWORDS: Record<Role, string> = {
  admin: 'admin-password-for-tests',
  operator: 'operator-password-for-tests',
  viewer: 'viewer-password-for-tests'
};

export interface TestApp {
  app: Express;
  db: Db;
  repos: Repositories;
}

export interface LoggedIn {
  agent: ReturnType<typeof request.agent>;
  csrf: string;
}

// Hashing is slow on purpose, so each test password is hashed only once.
const hashes: Record<string, string> = {};

async function hashOnce(password: string): Promise<string> {
  if (hashes[password] === undefined) {
    hashes[password] = await hashPassword(password);
  }
  return hashes[password];
}

/** Builds an app. Pass a file path instead of ':memory:' to test a restart. */
export async function setup(databasePath = ':memory:'): Promise<TestApp> {
  const db = openDatabase(databasePath);
  const config = loadConfig({ DATABASE_PATH: databasePath, LOG_REQUESTS: 'false' });
  const { app, repos } = createApp(config, db);

  const roles: Role[] = ['admin', 'operator', 'viewer'];
  for (const role of roles) {
    if (repos.users.findByUsername(role) === null) {
      repos.users.create(role, await hashOnce(PASSWORDS[role]), role);
    }
  }
  return { app, db, repos };
}

/** Logs in as admin, operator or viewer and returns a cookie-keeping agent plus the CSRF token. */
export async function login(app: Express, username: Role): Promise<LoggedIn> {
  const agent = request.agent(app);
  const res = await agent.post('/api/auth/login').send({ username, password: PASSWORDS[username] });
  if (res.status !== 200) {
    throw new Error('Login failed for ' + username);
  }
  return { agent, csrf: res.body.csrfToken };
}

/** The audit actions recorded so far, oldest first. */
export function auditActions(repos: Repositories): string[] {
  const actions: string[] = [];
  for (const event of repos.audit.list()) {
    actions.unshift(event.action);
  }
  return actions;
}
