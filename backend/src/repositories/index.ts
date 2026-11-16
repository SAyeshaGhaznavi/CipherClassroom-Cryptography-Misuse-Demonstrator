/**
 * All repositories in one object, so they can be passed around together.
 */
import type { Db } from '../database';
import { AuditRepository } from './auditRepository';
import { ExperimentRepository } from './experimentRepository';
import { SessionRepository } from './sessionRepository';
import { SettingsRepository } from './settingsRepository';
import { UserRepository } from './userRepository';

export interface Repositories {
  users: UserRepository;
  sessions: SessionRepository;
  experiments: ExperimentRepository;
  audit: AuditRepository;
  settings: SettingsRepository;
}

export function createRepositories(db: Db): Repositories {
  return {
    users: new UserRepository(db),
    sessions: new SessionRepository(db),
    experiments: new ExperimentRepository(db),
    audit: new AuditRepository(db),
    settings: new SettingsRepository(db)
  };
}
