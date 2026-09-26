'use strict';
/**
 * electron/crypto.js — SES Offline Workshop crypto core (main process only).
 *
 * Cryptographic architecture (crypto_version = 2):
 *
 *   Password ──► PBKDF2-HMAC-SHA-256, per-user random salt, DOMAIN-PREFIXED
 *               ("SES-AUTH-V2" prefix -> AUTH verifier, 100k iters;
 *                "SES-KEK-V2"   prefix -> KEK,           600k iters)
 *   KEK ──► AES-256-GCM unwrap of the random per-user DEK
 *   DEK ──► AES-256-GCM encryption of all financial data / backups
 *
 * Notes:
 *  - Node's built-in Argon2id is not available in this runtime (only scrypt),
 *    so per policy we use PBKDF2-HMAC-SHA-256 with >= 600,000 iterations for
 *    the key-encryption key. No weak KDF (MD5/SHA-1/plain SHA-256/un-salted)
 *    is ever used or accepted.
 *  - The password verifier and the KEK are derived with different domain
 *    prefixes, so possession of the verifier hash does NOT yield any key
 *    that can decrypt user data.
 *  - Every AES-GCM invocation uses a fresh 12-byte nonce from the OS CSPRNG.
 *  - GCM authentication failure ALWAYS rejects the whole payload (fail
 *    closed); nothing is ever parsed on tag mismatch.
 *
 * Container format (all binary parts stored as base64 strings inside JSON):
 *   { v:2, kdf:'PBKDF2-HMAC-SHA256', iv, ct, tag, ctr }
 */

const crypto = require('crypto');

const CRYPTO_VERSION = 2;
const KDF_NAME = 'PBKDF2-HMAC-SHA256';
const DEFAULT_AUTH_ITERATIONS = 100000;   // password verifier derivation
const DEFAULT_KEK_ITERATIONS = 600000;    // key-encryption-key derivation (policy minimum)
const SALT_BYTES = 32;                    // 32-byte random salt (policy preference)
const NONCE_BYTES = 12;                   // AES-GCM standard nonce
const KEY_BYTES = 32;                     // AES-256
const TAG_BYTES = 16;                     // GCM auth tag

// Domain separation prefixes (fixed UTF-8 constants mixed into PBKDF2 input).
const PREFIX_AUTH = Buffer.from('SES-AUTH-V2\0', 'utf8');
const PREFIX_KEK = Buffer.from('SES-KEK-V2\0', 'utf8');

// Maximum accepted sizes (defence against hostile/garbage files).
const MAX_CONTAINER_JSON = 64 * 1024 * 1024;  // 64 MiB serialized container
const MAX_PLAINTEXT_BYTES = 48 * 1024 * 1024; // decrypted payload ceiling

// Test-only escape hatch: real builds MUST keep this unset so production
// always uses full-strength PBKDF2 parameters.
const INSECURE_TEST_MODE = process.env.SES_INSECURE_TESTS === '1';
function authIterations() { return INSECURE_TEST_MODE ? 1000 : DEFAULT_AUTH_ITERATIONS; }
function kekIterations() { return INSECURE_TEST_MODE ? 1000 : DEFAULT_KEK_ITERATIONS; }

class SecurityError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'SecurityError';
    this.code = code;
  }
}

function randomBytes(n) {
  return crypto.randomBytes(n);
}

function newNonce() {
  return crypto.randomBytes(NONCE_BYTES);
}

function constantTimeEqual(a, b) {
  const ba = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
  const bb = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // Still perform a comparison against dummy data of equal length so the
    // observable timing does not depend on secret content.
    const dummy = Buffer.allocUnsafe(ba.length);
    crypto.timingSafeEqual(ba, dummy);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

function pbkdf2(password, saltBuf, iterations, keyLen, prefix) {
  const input = Buffer.concat([prefix, Buffer.from(String(password), 'utf8')]);
  return crypto.pbkdf2Sync(input, saltBuf, iterations, keyLen, 'sha256');
}

/** Derive the password *verifier* (auth purpose only — never a data key). */
function deriveAuthVerifier(password, saltB64, iterations = authIterations()) {
  return pbkdf2(password, decodeB64(saltB64, 'salt'), assertIterations(iterations), KEY_BYTES, PREFIX_AUTH);
}

/** Derive the Key Encryption Key (KEK) that unwraps the user's DEK. */
function deriveKek(password, saltB64, iterations = kekIterations()) {
  return pbkdf2(password, decodeB64(saltB64, 'salt'), assertIterations(iterations), KEY_BYTES, PREFIX_KEK);
}

/** Generate a fresh random Data Encryption Key (DEK). Never password-derived. */
function generateDek() {
  return randomBytes(KEY_BYTES);
}

function assertIterations(it) {
  const min = INSECURE_TEST_MODE ? 100 : 100000;
  if (!Number.isInteger(it) || it < min || it > 5000000) {
    throw new SecurityError('KDF_PARAMS_INVALID', 'Unsupported KDF iteration count.');
  }
  return it;
}

function decodeB64(s, what) {
  if (typeof s !== 'string' || s.length === 0 || s.length > 4 * 1024 * 1024) {
    throw new SecurityError('MALFORMED', `Invalid ${what} encoding.`);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    throw new SecurityError('MALFORMED', `Invalid ${what} encoding.`);
  }
  const buf = Buffer.from(s, 'base64');
  if (buf.toString('base64') !== s) {
    throw new SecurityError('MALFORMED', `Invalid ${what} encoding.`);
  }
  return buf;
}

function aesGcmEncrypt(keyBuf, plaintextBuf, aadStr) {
  if (!Buffer.isBuffer(keyBuf) || keyBuf.length !== KEY_BYTES) {
    throw new SecurityError('KEY_INVALID', 'Encryption key must be 32 bytes.');
  }
  const iv = newNonce();
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  if (aadStr) cipher.setAAD(Buffer.from(aadStr, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  return {
    v: CRYPTO_VERSION,
    kdf: KDF_NAME,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ctr: randomBytes(4).readUInt32BE(0), // entropy-filled per-write counter (nonce-reuse tripwire)
  };
}

function aesGcmDecrypt(keyBuf, container, aadStr) {
  validateContainer(container);
  const iv = decodeB64(container.iv, 'iv');
  const ct = decodeB64(container.ct, 'ct');
  const tag = decodeB64(container.tag, 'tag');
  if (iv.length !== NONCE_BYTES) throw new SecurityError('MALFORMED', 'Bad nonce size.');
  if (tag.length !== TAG_BYTES) throw new SecurityError('MALFORMED', 'Bad tag size.');
  if (!Buffer.isBuffer(keyBuf) || keyBuf.length !== KEY_BYTES) {
    throw new SecurityError('KEY_INVALID', 'Decryption key must be 32 bytes.');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  decipher.setAuthTag(tag);
  if (aadStr) decipher.setAAD(Buffer.from(aadStr, 'utf8'));
  let plain;
  try {
    plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (e) {
    // Wrong key OR tampered ciphertext/nonce/tag — fail closed, reveal nothing.
    zeroBuffer(ct);
    throw new SecurityError('AUTH_FAILED', 'Authentication failed.');
  }
  zeroBuffer(ct);
  return plain;
}

function validateContainer(container) {
  if (!container || typeof container !== 'object' || Array.isArray(container)) {
    throw new SecurityError('MALFORMED', 'Encrypted container must be an object.');
  }
  if (container.v !== CRYPTO_VERSION) {
    throw new SecurityError('UNSUPPORTED_VERSION', 'Unsupported crypto version.');
  }
  if (container.kdf !== KDF_NAME) {
    throw new SecurityError('UNSUPPORTED_VERSION', 'Unsupported KDF identifier.');
  }
  for (const f of ['iv', 'ct', 'tag']) {
    if (typeof container[f] !== 'string') {
      throw new SecurityError('MALFORMED', `Missing container field: ${f}`);
    }
  }
  if (
    container.ctr !== undefined &&
    (!Number.isInteger(container.ctr) || container.ctr < 0 || container.ctr > 0xffffffff)
  ) {
    throw new SecurityError('MALFORMED', 'Invalid container counter.');
  }
}

/** Encrypt an arbitrary JSON-serialisable value under a DEK. */
function encryptJson(dekBuf, value, aadStr) {
  const json = JSON.stringify(value);
  if (Buffer.byteLength(json) > MAX_PLAINTEXT_BYTES) {
    throw new SecurityError('TOO_LARGE', 'Payload exceeds maximum allowed size.');
  }
  return aesGcmEncrypt(dekBuf, Buffer.from(json, 'utf8'), aadStr);
}

/** Decrypt a container under a DEK and parse it as JSON. Fail-closed. */
function decryptJson(dekBuf, container, aadStr) {
  const plain = aesGcmDecrypt(dekBuf, container, aadStr);
  let obj;
  try {
    obj = JSON.parse(plain.toString('utf8'));
  } catch (e) {
    zeroBuffer(plain);
    throw new SecurityError('CORRUPT', 'Plaintext payload is not valid JSON.');
  }
  zeroBuffer(plain);
  return obj;
}

/** Wrap (encrypt) a DEK with a KEK. */
function wrapKey(kekBuf, dekBuf) {
  return aesGcmEncrypt(kekBuf, dekBuf, 'ses-dek-wrap-v2');
}

/** Unwrap (decrypt) a DEK with a KEK. Returns a NEW buffer (caller zeroes). */
function unwrapKey(kekBuf, wrappedContainer) {
  const dek = aesGcmDecrypt(kekBuf, wrappedContainer, 'ses-dek-wrap-v2');
  if (dek.length !== KEY_BYTES) {
    zeroBuffer(dek);
    throw new SecurityError('CORRUPT', 'Unwrapped key has invalid length.');
  }
  return dek;
}

/** Best-effort overwrite of sensitive buffers (no RAM-wipe guarantees). */
function zeroBuffer(buf) {
  try {
    if (Buffer.isBuffer(buf)) buf.fill(0);
  } catch (e) {
    /* ignore */
  }
}

module.exports = {
  CRYPTO_VERSION,
  KDF_NAME,
  DEFAULT_AUTH_ITERATIONS,
  DEFAULT_KEK_ITERATIONS,
  authIterations,
  kekIterations,
  SALT_BYTES,
  SecurityError,
  randomBytes,
  newNonce,
  constantTimeEqual,
  deriveAuthVerifier,
  deriveKek,
  generateDek,
  encryptJson,
  decryptJson,
  aesGcmEncrypt,
  aesGcmDecrypt,
  wrapKey,
  unwrapKey,
  zeroBuffer,
  validateContainer,
  MAX_CONTAINER_JSON,
};
