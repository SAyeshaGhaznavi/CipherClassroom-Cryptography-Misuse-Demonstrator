/**
 * Server settings, read from the .env file (see .env.example).
 * If a setting is missing, a safe default is used.
 */
import fs from 'node:fs';

export interface AppConfig {
  port: number;
  databasePath: string;
  /** Frontend addresses that are allowed to call the API (CORS). */
  corsOrigins: string[];
  /** How long a login session lasts. */
  sessionHours: number;
  /** true = send the session cookie only over HTTPS. */
  cookieSecure: boolean;
}

/** Loads the .env file into process.env, if the file exists. */
export function loadEnvFile(): void {
  if (fs.existsSync('.env')) {
    process.loadEnvFile('.env');
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  let port = 3001;
  if (env.PORT) {
    port = Number(env.PORT);
  }

  let databasePath = './data/cipherclassroom.db';
  if (env.DATABASE_PATH) {
    databasePath = env.DATABASE_PATH;
  }

  let corsOrigins = ['http://localhost:5173'];
  if (env.CORS_ORIGINS) {
    corsOrigins = env.CORS_ORIGINS.split(',').map((origin) => origin.trim());
  }

  let sessionHours = 8;
  if (env.SESSION_HOURS) {
    sessionHours = Number(env.SESSION_HOURS);
  }

  const cookieSecure = env.COOKIE_SECURE === 'true';

  return { port, databasePath, corsOrigins, sessionHours, cookieSecure };
}
