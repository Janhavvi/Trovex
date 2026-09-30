import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const PARAMETERS = { cost: 16384, blockSize: 8, parallelization: 1 };

export function validatePassword(password) {
  return typeof password === 'string'
    && password.length >= 12
    && password.length <= 128
    && /[A-Z]/.test(password)
    && /[a-z]/.test(password)
    && /\d/.test(password)
    && /[^A-Za-z0-9]/.test(password);
}

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scryptAsync(password, salt, 64, {
    N: PARAMETERS.cost,
    r: PARAMETERS.blockSize,
    p: PARAMETERS.parallelization,
    maxmem: 64 * 1024 * 1024,
  });
  return [
    'scrypt',
    PARAMETERS.cost,
    PARAMETERS.blockSize,
    PARAMETERS.parallelization,
    salt.toString('hex'),
    Buffer.from(derived).toString('hex'),
  ].join('$');
}

export async function verifyPassword(password, encoded) {
  const [algorithm, cost, blockSize, parallelization, saltHex, hashHex] = String(encoded).split('$');
  if (algorithm !== 'scrypt' || !cost || !blockSize || !parallelization || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  if (!expected.length) return false;
  const actual = Buffer.from(await scryptAsync(password, Buffer.from(saltHex, 'hex'), expected.length, {
    N: Number(cost),
    r: Number(blockSize),
    p: Number(parallelization),
    maxmem: 64 * 1024 * 1024,
  }));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
