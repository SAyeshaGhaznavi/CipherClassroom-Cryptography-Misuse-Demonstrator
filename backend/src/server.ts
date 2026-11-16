/**
 * Starts the API server:  npm run dev
 */
import { getPolicy } from 'cipherclassroom-engine';
import { createApp } from './app';
import { loadConfig, loadEnvFile } from './config';
import { openDatabase } from './database';

loadEnvFile();
const config = loadConfig();
const db = openDatabase(config.databasePath);
const { app, repos } = createApp(config, db);

// 127.0.0.1 = only this computer can reach the server.
app.listen(config.port, '127.0.0.1', () => {
  console.log('CipherClassroom API is running.');
  console.log('  Status and endpoint list: http://localhost:' + config.port + '/api');
  console.log('  Frontend allowed from:    ' + config.corsOrigins.join(', '));
  console.log('  Lab policy version:       ' + getPolicy().policyVersion);

  if (repos.users.findByUsername('admin') === null) {
    console.log('');
    console.log('No accounts yet. Stop the server and run "npm run seed" first.');
  }

  console.log('');
  console.log('Requests will be shown below:');
});
