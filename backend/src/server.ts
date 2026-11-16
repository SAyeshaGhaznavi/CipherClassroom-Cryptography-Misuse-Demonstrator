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
const { app } = createApp(config, db);

// 127.0.0.1 = only this computer can reach the server.
app.listen(config.port, '127.0.0.1', () => {
  console.log('CipherClassroom API running at http://localhost:' + config.port + '/api');
  console.log('Lab policy version: ' + getPolicy().policyVersion);
});
