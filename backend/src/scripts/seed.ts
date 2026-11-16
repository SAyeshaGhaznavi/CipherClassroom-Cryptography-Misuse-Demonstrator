/**
 * Creates the three accounts:  admin, operator and viewer.
 *
 *   npm run seed
 *
 * Passwords come from SEED_ADMIN_PASSWORD, SEED_OPERATOR_PASSWORD and
 * SEED_VIEWER_PASSWORD in .env. If one is empty, a random password is
 * generated and printed once. Accounts that already exist are not changed.
 */
import { loadConfig, loadEnvFile } from '../config';
import { openDatabase } from '../database';
import { createRepositories } from '../repositories';
import type { Role } from '../repositories/userRepository';
import { generatePassword, hashPassword, MIN_PASSWORD_LENGTH } from '../security/password';

const ACCOUNTS: { username: string; role: Role; envName: string }[] = [
  { username: 'admin', role: 'admin', envName: 'SEED_ADMIN_PASSWORD' },
  { username: 'operator', role: 'operator', envName: 'SEED_OPERATOR_PASSWORD' },
  { username: 'viewer', role: 'viewer', envName: 'SEED_VIEWER_PASSWORD' }
];

async function seed(): Promise<void> {
  loadEnvFile();
  const db = openDatabase(loadConfig().databasePath);
  const repos = createRepositories(db);

  for (const account of ACCOUNTS) {
    if (repos.users.findByUsername(account.username) !== null) {
      console.log(account.username + ' already exists, skipped.');
      continue;
    }

    let password = process.env[account.envName] || '';
    if (password === '') {
      password = generatePassword();
      console.log(account.username + ' password (shown only once): ' + password);
    } else if (password.length < MIN_PASSWORD_LENGTH) {
      throw new Error(account.envName + ' must be at least ' + MIN_PASSWORD_LENGTH + ' characters.');
    }

    repos.users.create(account.username, await hashPassword(password), account.role);
    repos.audit.append({
      actor: 'system',
      action: 'user.created',
      outcome: 'success',
      severity: 'info',
      detail: 'Created ' + account.role + ' account ' + account.username + '.'
    });
    console.log('Created ' + account.role + ' account: ' + account.username);
  }

  db.close();
}

seed().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
