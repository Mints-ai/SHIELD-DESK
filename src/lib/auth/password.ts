import "server-only";
import crypto from "node:crypto";

const KEY_LENGTH = 64;
const SCRYPT_COST = 16384;
const SCRYPT_BLOCK_SIZE = 8;
const SCRYPT_PARALLELIZATION = 1;

/**
 * Derives a cryptographic password hash using Scrypt.
 * Output format: <salt_hex>:<hash_hex>
 */
export async function hashPassword(password: string): Promise<string> {
  if (!password || typeof password !== "string") {
    throw new Error("Password must be a non-empty string");
  }

  const salt = crypto.randomBytes(16).toString("hex");

  return new Promise<string>((resolve, reject) => {
    crypto.scrypt(
      password,
      salt,
      KEY_LENGTH,
      {
        cost: SCRYPT_COST,
        blockSize: SCRYPT_BLOCK_SIZE,
        parallelization: SCRYPT_PARALLELIZATION,
      },
      (err, derivedKey) => {
        if (err) return reject(err);
        resolve(`${salt}:${derivedKey.toString("hex")}`);
      }
    );
  });
}

/**
 * Constant-time verification of password against stored scrypt hash.
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (!password || !storedHash || typeof storedHash !== "string") {
    return false;
  }

  const parts = storedHash.split(":");
  if (parts.length !== 2) {
    return false;
  }

  const [salt, expectedHashHex] = parts;
  if (!salt || !expectedHashHex) {
    return false;
  }

  return new Promise<boolean>((resolve) => {
    crypto.scrypt(
      password,
      salt,
      KEY_LENGTH,
      {
        cost: SCRYPT_COST,
        blockSize: SCRYPT_BLOCK_SIZE,
        parallelization: SCRYPT_PARALLELIZATION,
      },
      (err, derivedKey) => {
        if (err) return resolve(false);

        try {
          const derivedBuf = derivedKey;
          const expectedBuf = Buffer.from(expectedHashHex, "hex");

          if (derivedBuf.length !== expectedBuf.length) {
            return resolve(false);
          }

          resolve(crypto.timingSafeEqual(derivedBuf, expectedBuf));
        } catch {
          resolve(false);
        }
      }
    );
  });
}
