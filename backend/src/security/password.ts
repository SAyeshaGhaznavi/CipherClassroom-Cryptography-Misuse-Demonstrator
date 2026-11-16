/**
 * Password hashing with scrypt (built into Node.js).
 *
 * A password is never stored. We store:  scrypt$<salt>$<hash>
 * The salt is random for every password, so two users with the same
 * password still get different hashes.
 */
import crypto from 'node:crypto';

const KEY_LENGTH = 64;
// N = 32768 makes each guess cost real time and memory.
const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export const MIN_PASSWORD_LENGTH = 12;

function scrypt(password: string, salt: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, KEY_LENGTH, SCRYPT_OPTIONS, (error, key) => {
      if (error) {
        reject(error);
      } else {
        resolve(key);
      }
    });
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await scrypt(password, salt);
  return 'scrypt$' + salt + '$' + hash.toString('hex');
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') {
    return false;
  }
  const salt = parts[1];
  const expected = Buffer.from(parts[2], 'hex');
  const actual = await scrypt(password, salt);
  // timingSafeEqual takes the same time whether the first or last byte differs.
  return crypto.timingSafeEqual(actual, expected);
}

/** A random password for the seed and reset scripts. */
export function generatePassword(): string {
  return crypto.randomBytes(18).toString('base64url');
}
