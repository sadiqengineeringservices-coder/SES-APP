'use strict';
/**
 * electron/storage.js — secure local storage primitives (main process only).
 *
 * Responsibilities:
 *  - Application data lives ONLY under %APPDATA%/SES Offline Workshop on
 *    Windows and ~/.local/share/SES Offline Workshop elsewhere. Never in the
 *    project/source/public directories.
 *  - Atomic, durable writes: temp file -> fsync -> rename -> directory fsync.
 *    Temp files are created inside the SAME private directory (never os.tmp)
 *    so plaintext/sensitive data never touches shared temp locations.
 *  - Owner-only permissions (0700 dirs / 0600 files) where the OS supports it.
 *  - Symlink rejection for all security-relevant paths.
 *  - Strict identifier validation before ANY path is constructed: user IDs
 *    must be canonical UUIDs, so renderer-supplied strings can never produce
 *    path traversal (`../`), absolute paths, null bytes, separators, or
 *    unicode/case collisions.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { SecurityError } = require('./crypto');

const APP_DIR_NAME = 'SES Offline Workshop';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function appDataDir() {
  if (process.platform === 'win32') {
    const base = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(base, APP_DIR_NAME);
  }
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', APP_DIR_NAME);
  }
  const xdg = process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
  return path.join(xdg, APP_DIR_NAME);
}

function ensurePrivateDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dirPath, 0o700);
  } catch (e) {
    /* best effort on platforms without POSIX modes */
  }
  return dirPath;
}

/** Reject anything that is not a canonical lowercase UUID. */
function assertSafeUserId(userId) {
  if (typeof userId !== 'string' || !UUID_RE.test(userId)) {
    throw new SecurityError('INVALID_USER_ID', 'User id must be a canonical UUID.');
  }
  return userId;
}

/**
 * Validate an arbitrary *name* string coming from untrusted input
 * (usernames, export file names). Returns the NFC-normalised name or throws.
 */
const RESERVED_NAMES = new Set([
  'con', 'prn', 'aux', 'nul',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

function validateName(name, what = 'name', maxLen = 64) {
  if (typeof name !== 'string') {
    throw new SecurityError('INVALID_INPUT', `${what} must be a string.`);
  }
  const nfc = name.normalize('NFC');
  if (nfc.length === 0 || nfc.length > maxLen) {
    throw new SecurityError('INVALID_INPUT', `${what} length must be 1..${maxLen}.`);
  }
  if (nfc.includes('\0')) {
    throw new SecurityError('INVALID_INPUT', `${what} contains a null byte.`);
  }
  if (nfc.includes('/') || nfc.includes('\\')) {
    throw new SecurityError('INVALID_INPUT', `${what} contains a path separator.`);
  }
  if (nfc === '.' || nfc === '..' || nfc.includes('..')) {
    throw new SecurityError('INVALID_INPUT', `${what} contains a traversal sequence.`);
  }
  if (path.isAbsolute(nfc)) {
    throw new SecurityError('INVALID_INPUT', `${what} must not be an absolute path.`);
  }
  if (/[<>:"|?*]/.test(nfc)) {
    throw new SecurityError('INVALID_INPUT', `${what} contains forbidden characters.`);
  }
  if (/[.\s]$/.test(nfc)) {
    throw new SecurityError('INVALID_INPUT', `${what} must not end with a dot or space.`);
  }
  if (RESERVED_NAMES.has(nfc.toLowerCase())) {
    throw new SecurityError('INVALID_INPUT', `${what} is a reserved name.`);
  }
  // Only allow letters (any script), digits, space and simple punctuation.
  if (!/^[\p{L}\p{N}][\p{L}\p{N} ._'\-@#&\u2019]*$/u.test(nfc)) {
    throw new SecurityError('INVALID_INPUT', `${what} contains disallowed characters.`);
  }
  return nfc;
}

function lstatIfLink(p) {
  try {
    const st = fs.lstatSync(p);
    return st;
  } catch (e) {
    return null;
  }
}

/** Refuse to read/write through symlinks/junctions on the final component. */
function assertNotSymlink(filePath) {
  const st = lstatIfLink(filePath);
  if (st && st.isSymbolicLink()) {
    throw new SecurityError('SYMLINK_REJECTED', 'Refusing to operate on a symbolic link.');
  }
}

function openDirHandle(dirPath) {
  try {
    return fs.openSync(dirPath, process.platform === 'win32' ? 'r' : fs.constants.O_RDONLY);
  } catch (e) {
    return null;
  }
}

/**
 * Atomic write: serialize -> write temp (same private dir) -> fsync ->
 * rename (atomic replace) -> fsync directory. Mode 0600. Never plaintext
 * outside the owner-only directory; temp file removed on any failure.
 */
function atomicWriteFileSync(filePath, dataBufOrStr) {
  const dir = path.dirname(filePath);
  ensurePrivateDir(dir);
  assertNotSymlink(filePath);
  const tmp = path.join(dir, `.${path.basename(filePath)}.tmp-${process.pid}-${Date.now()}`);
  let fd = null;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, dataBufOrStr);
    try {
      fs.fsyncSync(fd);
    } catch (e) {
      /* fsync unsupported on some platforms/files */
    }
    fs.closeSync(fd);
    fd = null;
    try {
      fs.chmodSync(tmp, 0o600);
    } catch (e) {
      /* best effort */
    }
    fs.renameSync(tmp, filePath);
    const dh = openDirHandle(dir);
    if (dh !== null) {
      try {
        fs.fsyncSync(dh);
      } catch (e) {
        /* best effort */
      }
      try {
        fs.closeSync(dh);
      } catch (e) {
        /* ignore */
      }
    }
  } catch (err) {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch (e) { /* ignore */ }
    }
    try { fs.unlinkSync(tmp); } catch (e) { /* ignore */ }
    throw err;
  }
}

function readFileSyncCapped(filePath, maxBytes) {
  assertNotSymlink(filePath);
  let st;
  try {
    st = fs.statSync(filePath);
  } catch (e) {
    throw new SecurityError('NOT_FOUND', 'File not found.');
  }
  if (!st.isFile()) throw new SecurityError('INVALID_FILE', 'Not a regular file.');
  if (st.size > maxBytes) {
    throw new SecurityError('TOO_LARGE', 'File exceeds maximum allowed size.');
  }
  return fs.readFileSync(filePath);
}

function readJsonFileCapped(filePath, maxBytes) {
  const buf = readFileSyncCapped(filePath, maxBytes);
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch (e) {
    throw new SecurityError('CORRUPT', 'File is not valid JSON.');
  }
}

function fileExists(p) {
  try {
    return fs.statSync(p).isFile();
  } catch (e) {
    return false;
  }
}

module.exports = {
  appDataDir,
  ensurePrivateDir,
  assertSafeUserId,
  validateName,
  assertNotSymlink,
  atomicWriteFileSync,
  readFileSyncCapped,
  readJsonFileCapped,
  fileExists,
};
