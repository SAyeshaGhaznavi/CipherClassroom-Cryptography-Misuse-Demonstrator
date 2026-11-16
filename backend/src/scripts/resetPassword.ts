/**
 * Recovery: gives an account a new random password and logs it out everywhere.
 * Use it when a password (for example the admin password) is lost.
 *
 *   npm run reset-password -- admin
 */
import { loadConfig, loadEnvFile } from '../config';
import { openDatabase } from '../database';
import { createRepositories } from '../repositories';
import { generatePassword, hashPassword } from '../security/password';

async function resetPassword(): Promise<void> {
  const username = process.argv[2];
  if (!username) {
    throw new Error('Usage: npm run reset-password -- <username>');
  }

  loadEnvFile();
  const db = openDatabase(loadConfig().databasePath);
  const repos = createRepositories(db);

  const user = repos.users.findByUsername(username);
  if (user === null) {
    db.close();
    throw new Error('No account named "' + username + '".');
  }

  const password = generatePassword();
  repos.users.setPasswordHash(user.id, await hashPassword(password));
  repos.sessions.deleteAllForUser(user.id);
  repos.audit.append({
    actor: 'system',
    action: 'user.password_reset',
    outcome: 'success',
    severity: 'warning',
    detail: 'Password of ' + user.username + ' was reset from the command line.'
  });
  db.close();

  console.log('New password for ' + user.username + ' (shown only once): ' + password);
}

resetPassword().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
