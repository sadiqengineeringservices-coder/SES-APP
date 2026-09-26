'use strict';
/**
 * electron/auth.js — multi-user authentication, session and throttle manager.
 * (Main process only. The renderer never sees salts, verifiers, KEKs or DEKs.)
 *
 * On-disk layout (all under the owner-only app data directory):
 *   registry.json                    public user registry (NO secrets)
 *   throttle.json                    per-username anti-brute-force state
 *   users/<user_id>/data.enc         AES-256-GCM encrypted finance data
 *   users/<user_id>/meta.json        wrapped DEK + KDF params (registry mirror)
 *   legacy_plaintext_report.json     report of quarantined legacy plaintext files
 *
 * Security properties:
 *  - Passwords are never stored; only a domain-separated PBKDF2 verifier.
 *  - The verifier is NOT the data key (separate "SES-KEK-V2" derivation).
 *  - A random per-user DEK wraps nothing but is itself wrapped by the KEK,
 *    so password changes re-wrap the DEK without touching financial data.
 *  - Sessions live only in main-process memory; every operation checks
 *    token validity AND that the requested userId equals the session's.
 *  - Async work binds to a session epoch: after logout / user switch, any
 *    late save from the previous session is rejected.
 *  - Anti-brute-force: exponential, persisted failure counters with monotonic
 *    delays; survives app restart and username cycling (per-username buckets).
 */

const path = require('path');
const crypto = require('crypto');
const C = require('./crypto');
const S = require('./storage');

const REGISTRY_VERSION = 2;
const USERNAME_MIN = 3;
const USERNAME_MAX = 32;
const PASSWORD_MIN = 10;
const PASSWORD_MAX = 256;
const MAX_USERS = 100;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8h idle expiry
const THROTTLE_THRESHOLD = 3;              // failures before delay kicks in
const THROTTLE_BASE_MS = 2000;             // 2s, doubling each further failure
const THROTTLE_MAX_MS = 5 * 60 * 1000;     // cap at 5 minutes
const THROTTLE_RESET_AFTER_MS = 15 * 60 * 1000; // decay window after last attempt

class AuthError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'AuthError';
    this.code = code;
  }
}

function newUserId() {
  return crypto.randomUUID();
}

function newSessionToken() {
  return C.randomBytes(32).toString('base64url');
}

/** Casefolded, NFC-normalised comparison key (prevents case/unicode collisions). */
function unameKey(username) {
  return username.normalize('NFC').toLowerCase();
}

function validateUsernameShape(username) {
  if (typeof username !== 'string') throw new AuthError('INVALID_USERNAME', 'Invalid username.');
  const nfc = username.normalize('NFC').trim();
  if (nfc.length < USERNAME_MIN || nfc.length > USERNAME_MAX) {
    throw new AuthError('INVALID_USERNAME', `Username must be ${USERNAME_MIN}-${USERNAME_MAX} characters.`);
  }
  // Throws on traversal/separators/null bytes/reserved names/control chars.
  S.validateName(nfc, 'username', USERNAME_MAX);
  if (/^[._\s]+|[._\s]+$/.test(nfc)) {
    throw new AuthError('INVALID_USERNAME', 'Username has invalid leading/trailing characters.');
  }
  return nfc;
}

function validatePasswordShape(password) {
  if (typeof password !== 'string') throw new AuthError('INVALID_PASSWORD', 'Invalid password.');
  if (password.length < PASSWORD_MIN) {
    throw new AuthError('INVALID_PASSWORD', `Password must be at least ${PASSWORD_MIN} characters. Length beats complexity.`);
  }
  if (password.length > PASSWORD_MAX) {
    throw new AuthError('INVALID_PASSWORD', `Password too long (max ${PASSWORD_MAX}).`);
  }
  // Reject control characters (protects logs/terminals), but no arbitrary
  // composition rules — length is the primary policy.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(password)) {
    throw new AuthError('INVALID_PASSWORD', 'Password contains control characters.');
  }
  return password;
}

class AuthManager {
  /**
   * @param {object} opts
   * @param {string} [opts.rootDir] override storage root (tests use temp dirs)
   */
  constructor(opts = {}) {
    this.root = opts.rootDir || S.appDataDir();
    this.usersDir = path.join(this.root, 'users');
    this.registryPath = path.join(this.root, 'registry.json');
    this.throttlePath = path.join(this.root, 'throttle.json');
    this.legacyReportPath = path.join(this.root, 'legacy_plaintext_report.json');
    S.ensurePrivateDir(this.root);
    S.ensurePrivateDir(this.usersDir);

    /** @type {Map<string, object>} userId -> registry record */
    this.usersById = new Map();
    /** @type {Map<string, string>} normalized username -> userId */
    this.usersByName = new Map();
    /** @type {Map<string, object>} sessionToken -> session */
    this.sessions = new Map();
    /** Monotonic epoch used to invalidate async work from old sessions. */
    this.epoch = 1;
    this.saveMutex = false;

    this._loadRegistry();
    this._migrateLegacyRegistry();
    this._quarantineLegacyPlaintext();
  }

  /* ------------------------------------------------------------------ *
   * Registry (public metadata; integrity-checked shape, never secrets) *
   * ------------------------------------------------------------------ */

  _loadRegistry() {
    if (!S.fileExists(this.registryPath)) return;
    let reg;
    try {
      reg = S.readJsonFileCapped(this.registryPath, 8 * 1024 * 1024);
    } catch (e) {
      // Fail closed: a corrupt registry must not silently create a fresh,
      // empty one over the top of it. Rename aside for manual recovery.
      const aside = this.registryPath + '.corrupt-' + Date.now();
      try { require('fs').renameSync(this.registryPath, aside); } catch (e2) { /* ignore */ }
      throw new AuthError(
        'REGISTRY_CORRUPT',
        `User registry unreadable; preserved at ${aside} for manual recovery.`
      );
    }
    if (!reg || typeof reg !== 'object' || !Array.isArray(reg.users)) return;
    for (const u of reg.users) {
      try {
        const rec = this._validateRegistryRecord(u);
        if (rec) this._indexUser(rec);
      } catch (e) {
        // Skip malformed records rather than trusting them.
      }
    }
  }

  _validateRegistryRecord(u) {
    if (!u || typeof u !== 'object') return null;
    if (typeof u.user_id !== 'string') return null;
    S.assertSafeUserId(u.user_id);
    const username = validateUsernameShape(String(u.username || ''));
    if (typeof u.auth_salt !== 'string' || typeof u.auth_verifier !== 'string') return null;
    if (typeof u.kek_salt !== 'string') return null;
    if (!u.wrapped_dek || typeof u.wrapped_dek !== 'object') return null;
    C.validateContainer(u.wrapped_dek);
    if (!Number.isInteger(u.kek_iterations) || u.kek_iterations < C.kekIterations()) return null;
    if (u.crypto_version !== C.CRYPTO_VERSION) return null;
    return {
      user_id: u.user_id,
      username,
      display_name: typeof u.display_name === 'string' ? u.display_name.slice(0, 64) : username,
      auth_salt: u.auth_salt,
      auth_iterations: Number.isInteger(u.auth_iterations) ? u.auth_iterations : C.authIterations(),
      auth_verifier: u.auth_verifier,
      kek_salt: u.kek_salt,
      kek_iterations: u.kek_iterations,
      wrapped_dek: u.wrapped_dek,
      crypto_version: u.crypto_version,
      created_at: typeof u.created_at === 'string' ? u.created_at : new Date().toISOString(),
      last_login_at: typeof u.last_login_at === 'string' ? u.last_login_at : null,
    };
  }

  _indexUser(rec) {
    this.usersById.set(rec.user_id, rec);
    this.usersByName.set(unameKey(rec.username), rec.user_id);
  }

  _writeRegistry() {
    const payload = {
      version: REGISTRY_VERSION,
      crypto_version: C.CRYPTO_VERSION,
      kdf: C.KDF_NAME,
      users: [...this.usersById.values()],
    };
    S.atomicWriteFileSync(this.registryPath, JSON.stringify(payload, null, 2));
  }

  /* ------------------------------------------------------------------ *
   * Legacy migration (v1 registry had NO authentication at all)         *
   * ------------------------------------------------------------------ */

  _migrateLegacyRegistry() {
    const legacyPath = path.join(this.root, 'registry.json.v1');
    if (!S.fileExists(legacyPath)) return;
    // v1 stored { folder, users:[{id,name}] } with zero authentication.
    // We do NOT auto-create accounts from it (no password exists); we keep
    // the file untouched for reference and simply ignore it. Accounts must
    // be registered explicitly; existing plaintext data is quarantined below
    // and can be imported through an authenticated session.
    try { require('fs').chmodSync(legacyPath, 0o600); } catch (e) { /* ignore */ }
  }

  /**
   * Any *.json / *.xlsx plaintext files left in the data root by the old
   * build (finance data in the clear) are moved into a private quarantine
   * directory and reported. They are NEVER deleted and NEVER loaded.
   */
  _quarantineLegacyPlaintext() {
    const qdir = path.join(this.root, 'quarantine');
    let entries;
    try {
      entries = require('fs').readdirSync(this.root, { withFileTypes: true });
    } catch (e) {
      return;
    }
    const moved = [];
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      const name = ent.name;
      if (name === 'registry.json' || name === 'throttle.json' || name === 'legacy_plaintext_report.json') continue;
      if (!/\.(json|xlsx|xls|csv)$/i.test(name)) continue;
      if (name.startsWith('registry.json.')) continue;
      S.ensurePrivateDir(qdir);
      const from = path.join(this.root, name);
      const to = path.join(qdir, `${Date.now()}-${name}`);
      try {
        require('fs').renameSync(from, to);
        moved.push({ original: name, quarantined_to: to, reason: 'plaintext_financial_data_removed_by_hardening' });
      } catch (e) {
        moved.push({ original: name, error: 'quarantine_failed' });
      }
    }
    if (moved.length > 0) {
      S.atomicWriteFileSync(
        this.legacyReportPath,
        JSON.stringify({ generated_at: new Date().toISOString(), files: moved }, null, 2)
      );
    }
  }

  /* ------------------------------------------------------------------ *
   * Anti-brute-force throttle                                           *
   * ------------------------------------------------------------------ */

  _loadThrottle() {
    if (!S.fileExists(this.throttlePath)) return {};
    try {
      const t = S.readJsonFileCapped(this.throttlePath, 1024 * 1024);
      return t && typeof t === 'object' ? t : {};
    } catch (e) {
      return {};
    }
  }

  _saveThrottle(t) {
    S.atomicWriteFileSync(this.throttlePath, JSON.stringify(t));
  }

  _throttleCheck(key) {
    const t = this._loadThrottle();
    const e = t[key];
    if (!e || !Number.isInteger(e.fails) || e.fails < THROTTLE_THRESHOLD) return;
    const now = Date.now();
    const sinceLast = now - (e.last || 0);
    if (sinceLast > THROTTLE_RESET_AFTER_MS) return; // decay window passed
    const delay = Math.min(THROTTLE_BASE_MS * Math.pow(2, e.fails - THROTTLE_THRESHOLD), THROTTLE_MAX_MS);
    const waitMs = Math.max(0, delay - sinceLast);
    if (waitMs > 0) {
      const err = new AuthError('THROTTLED', `Too many attempts. Wait ${Math.ceil(waitMs / 1000)}s.`);
      err.retryAfterMs = waitMs;
      throw err;
    }
  }

  _throttleRecordFailure(key) {
    const t = this._loadThrottle();
    const e = t[key] || { fails: 0, last: 0 };
    // decay
    if (Date.now() - (e.last || 0) > THROTTLE_RESET_AFTER_MS) e.fails = 0;
    e.fails += 1;
    e.last = Date.now();
    t[key] = e;
    this._saveThrottle(t);
  }

  _throttleClear(key) {
    const t = this._loadThrottle();
    if (t[key]) {
      delete t[key];
      this._saveThrottle(t);
    }
  }

  /* ------------------------------------------------------------------ *
   * Registration / login / password change                              *
   * ------------------------------------------------------------------ */

  listUsernames() {
    return [...this.usersById.values()].map((u) => ({
      user_id: u.user_id,
      username: u.username,
      display_name: u.display_name,
    }));
  }

  register(username, password, displayName) {
    const uname = validateUsernameShape(username);
    const pw = validatePasswordShape(password);
    if (this.usersByName.has(unameKey(uname))) {
      throw new AuthError('USERNAME_TAKEN', 'That username is already registered.');
    }
    if (this.usersById.size >= MAX_USERS) {
      throw new AuthError('LIMIT', 'Maximum number of local users reached.');
    }
    const user_id = newUserId();
    const authSalt = C.randomBytes(C.SALT_BYTES).toString('base64');
    const kekSalt = C.randomBytes(C.SALT_BYTES).toString('base64');
    const verifier = C.deriveAuthVerifier(pw, authSalt, C.authIterations());
    const kek = C.deriveKek(pw, kekSalt, C.kekIterations());
    const dek = C.generateDek();
    let wrapped;
    let verifierB64;
    try {
      verifierB64 = verifier.toString('base64');
      wrapped = C.wrapKey(kek, dek);
    } finally {
      C.zeroBuffer(kek);
      C.zeroBuffer(verifier);
    }
    const rec = {
      user_id,
      username: uname,
      display_name: (typeof displayName === 'string' ? displayName.trim().slice(0, 64) : '') || uname,
      auth_salt: authSalt,
      auth_iterations: C.authIterations(),
      auth_verifier: verifierB64,
      kek_salt: kekSalt,
      kek_iterations: C.kekIterations(),
      wrapped_dek: wrapped,
      crypto_version: C.CRYPTO_VERSION,
      created_at: new Date().toISOString(),
      last_login_at: null,
    };
    this._indexUser(rec);
    try {
      this._writeRegistry();
      // Fresh user starts with an empty encrypted datastore (DEK kept only
      // long enough to bootstrap it, then zeroed).
      const empty = { version: 1, clients: [], projects: [], expenses: [], payments: [] };
      this._writeUserDataEncrypted(user_id, empty, dek);
    } catch (e) {
      this.usersById.delete(user_id);
      this.usersByName.delete(unameKey(uname));
      throw e;
    } finally {
      C.zeroBuffer(dek);
    }
    return { user_id, username: uname };
  }

  login(username, password) {
    const unameRaw = typeof username === 'string' ? username.normalize('NFC').trim() : '';
    const pw = typeof password === 'string' ? password : '';
    // Throttle BEFORE touching the registry (uniform cost, no user enum oracle).
    const key = unameKey(unameRaw || '?');
    this._throttleCheck(key);
    this._throttleCheck('__any__'); // global bucket defeats username spraying

    const userId = this.usersByName.get(key);
    const rec = userId ? this.usersById.get(userId) : null;
    if (!rec || pw.length === 0 || pw.length > PASSWORD_MAX) {
      this._throttleRecordFailure(key);
      this._throttleRecordFailure('__any__');
      // Constant-ish work even for unknown users (avoid timing enumeration).
      const dummySalt = C.randomBytes(C.SALT_BYTES).toString('base64');
      C.zeroBuffer(C.deriveAuthVerifier(pw || 'x', dummySalt, C.authIterations()));
      throw new AuthError('BAD_CREDENTIALS', 'Invalid username or password.');
    }
    const candidate = C.deriveAuthVerifier(pw, rec.auth_salt, rec.auth_iterations);
    const stored = Buffer.from(rec.auth_verifier, 'base64');
    const ok = C.constantTimeEqual(candidate, stored);
    C.zeroBuffer(candidate);
    C.zeroBuffer(stored);
    if (!ok) {
      this._throttleRecordFailure(key);
      this._throttleRecordFailure('__any__');
      throw new AuthError('BAD_CREDENTIALS', 'Invalid username or password.');
    }
    this._throttleClear(key);

    const kek = C.deriveKek(pw, rec.kek_salt, rec.kek_iterations);
    let dek;
    try {
      dek = C.unwrapKey(kek, rec.wrapped_dek);
    } catch (e) {
      C.zeroBuffer(kek);
      // Verifier matched but unwrap failed: registry/data tampering.
      throw new AuthError('KEY_UNWRAP_FAILED', 'Secure store integrity check failed. Contact support with the app data folder contents listing (no file contents).');
    } finally {
      C.zeroBuffer(kek);
    }

    const session = {
      token: newSessionToken(),
      user_id: rec.user_id,
      username: rec.username,
      display_name: rec.display_name,
      dek,                       // sensitive: zeroed on logout
      epoch: this.epoch,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      invalidated: false,
    };
    this.sessions.set(session.token, session);
    rec.last_login_at = new Date().toISOString();
    try { this._writeRegistry(); } catch (e) { /* non-fatal */ }
    return {
      token: session.token,
      user_id: session.user_id,
      username: session.username,
      display_name: session.display_name,
    };
  }

  changePassword(token, currentPassword, newPassword) {
    const s = this._requireSession(token);
    const rec = this._requireUser(s.user_id);
    const npw = validatePasswordShape(newPassword);
    const cur = C.deriveAuthVerifier(currentPassword || '', rec.auth_salt, rec.auth_iterations);
    const stored = Buffer.from(rec.auth_verifier, 'base64');
    const ok = C.constantTimeEqual(cur, stored);
    C.zeroBuffer(cur);
    C.zeroBuffer(stored);
    if (!ok) throw new AuthError('BAD_CREDENTIALS', 'Current password is incorrect.');

    // Re-wrap the SAME random DEK under a NEW KEK — financial data untouched.
    const newKekSalt = C.randomBytes(C.SALT_BYTES).toString('base64');
    const newAuthSalt = C.randomBytes(C.SALT_BYTES).toString('base64');
    const newVerifier = C.deriveAuthVerifier(npw, newAuthSalt, C.authIterations());
    const newKek = C.deriveKek(npw, newKekSalt, C.kekIterations());
    const newWrapped = C.wrapKey(newKek, s.dek);
    C.zeroBuffer(newKek);
    C.zeroBuffer(newVerifier);

    rec.auth_salt = newAuthSalt;
    rec.auth_verifier = newVerifier.toString('base64');
    C.zeroBuffer(newVerifier);
    rec.kek_salt = newKekSalt;
    rec.kek_iterations = C.kekIterations();
    rec.wrapped_dek = newWrapped;
    this._writeRegistry();
    return { changed: true };
  }

  /* ------------------------------------------------------------------ *
   * Session management                                                  *
   * ------------------------------------------------------------------ */

  _requireSession(token) {
    const s = typeof token === 'string' ? this.sessions.get(token) : null;
    if (!s || s.invalidated) throw new AuthError('NO_SESSION', 'Not authenticated.');
    if (Date.now() - s.lastActivity > SESSION_TTL_MS) {
      this.logout(token);
      throw new AuthError('SESSION_EXPIRED', 'Session expired.');
    }
    s.lastActivity = Date.now();
    return s;
  }

  _requireUser(userId) {
    S.assertSafeUserId(userId);
    const rec = this.usersById.get(userId);
    if (!rec) throw new AuthError('UNKNOWN_USER', 'Unknown user.');
    return rec;
  }

  /**
   * Core authorization gate for every data operation:
   * session must exist, match the requested userId, and belong to the
   * current epoch (so post-logout / post-switch async work fails closed).
   */
  authorize(token, userId) {
    const s = this._requireSession(token);
    if (typeof userId !== 'string' || userId !== s.user_id) {
      throw new AuthError('FORBIDDEN', 'Operation targets a different user than the active session.');
    }
    if (s.epoch !== this.epoch) {
      throw new AuthError('STALE_SESSION', 'Session superseded by a newer login/logout.');
    }
    return s;
  }

  getSessionInfo(token) {
    const s = this._requireSession(token);
    return { user_id: s.user_id, username: s.username, display_name: s.display_name };
  }

  logout(token) {
    const s = typeof token === 'string' ? this.sessions.get(token) : null;
    if (!s) return { loggedOut: false };
    s.invalidated = true;
    C.zeroBuffer(s.dek);           // destroy derived key material immediately
    s.dek = null;
    this.sessions.delete(token);
    this.epoch += 1;               // invalidate any other outstanding sessions
    return { loggedOut: true };
  }

  logoutAll() {
    for (const s of this.sessions.values()) {
      s.invalidated = true;
      C.zeroBuffer(s.dek);
      s.dek = null;
    }
    this.sessions.clear();
    this.epoch += 1;
  }

  /* ------------------------------------------------------------------ *
   * Encrypted per-user data store                                       *
   * ------------------------------------------------------------------ */

  _userDataPath(userId) {
    S.assertSafeUserId(userId);
    return path.join(this.usersDir, userId, 'data.enc');
  }

  _writeUserDataEncrypted(userId, value, dekBuf) {
    const container = C.encryptJson(dekBuf, value, `ses-data:${userId}`);
    const p = this._userDataPath(userId);
    S.ensurePrivateDir(path.dirname(p));
    S.atomicWriteFileSync(p, JSON.stringify(container));
  }

  _readUserDataDecrypted(userId, dekBuf) {
    const p = this._userDataPath(userId);
    if (!S.fileExists(p)) {
      return { version: 1, clients: [], projects: [], expenses: [], payments: [] };
    }
    const container = S.readJsonFileCapped(p, C.MAX_CONTAINER_JSON);
    return C.decryptJson(dekBuf, container, `ses-data:${userId}`);
  }

  loadData(token, userId) {
    const s = this.authorize(token, userId);
    return this._readUserDataDecrypted(s.user_id, s.dek);
  }

  /**
   * Serialized, session-bound save. The session identity is captured BEFORE
   * awaiting the mutex; if the user logs out or switches while queued, the
   * save is rejected (prevents cross-user / stale-session writes).
   */
  async saveData(token, userId, value) {
    const s = this.authorize(token, userId);
    const expectedEpoch = s.epoch;
    const expectedToken = s.token;
    // Serialize concurrent saves (simple async mutex).
    while (this.saveMutex) {
      await new Promise((r) => setTimeout(r, 20));
    }
    this.saveMutex = true;
    try {
      const cur = this.sessions.get(expectedToken);
      if (!cur || cur.invalidated || cur.epoch !== expectedEpoch || this.epoch !== expectedEpoch) {
        throw new AuthError('STALE_SESSION', 'Save rejected: session no longer active.');
      }
      this._writeUserDataEncrypted(cur.user_id, value, cur.dek);
      return { saved: true };
    } finally {
      this.saveMutex = false;
    }
  }

  /* ------------------------------------------------------------------ *
   * Secure backup (encrypted, self-contained, password re-confirmed)    *
   * ------------------------------------------------------------------ */

  /**
   * Backups are decryptable ONLY with the user's own credentials: the random
   * DEK is embedded wrapped under a fresh AES key derived from the confirmed
   * password + a fresh backup salt (same PBKDF2 parameters as the live KEK).
   * The password itself is never stored inside the backup.
   */
  createBackup(token, userId, confirmPassword) {
    const s = this.authorize(token, userId);
    if (typeof confirmPassword !== 'string' || confirmPassword.length === 0 || confirmPassword.length > PASSWORD_MAX) {
      throw new AuthError('CONFIRM_PASSWORD', 'Confirm your password to create an encrypted backup.');
    }
    // Re-confirm the credential before producing a credential-protected file.
    const rec = this._requireUser(s.user_id);
    const cur = C.deriveAuthVerifier(confirmPassword, rec.auth_salt, rec.auth_iterations);
    const stored = Buffer.from(rec.auth_verifier, 'base64');
    const ok = C.constantTimeEqual(cur, stored);
    C.zeroBuffer(cur);
    C.zeroBuffer(stored);
    if (!ok) throw new AuthError('BAD_CREDENTIALS', 'Password confirmation failed.');
    const data = this._readUserDataDecrypted(s.user_id, s.dek);
    const saltB64 = C.randomBytes(C.SALT_BYTES).toString('base64');
    const backupKek = C.deriveKek(confirmPassword, saltB64, C.kekIterations());
    let wrappedDek;
    try {
      wrappedDek = C.wrapKey(backupKek, s.dek);
    } finally {
      C.zeroBuffer(backupKek);
    }
    const payloadContainer = C.encryptJson(s.dek, data, 'ses-backup-payload-v2');
    return {
      format: 'ses-secure-backup',
      format_version: 2,
      crypto_version: C.CRYPTO_VERSION,
      kdf: C.KDF_NAME,
      kdf_iterations: C.kekIterations(),
      salt: saltB64,
      wrapped_dek: wrappedDek,
      payload: payloadContainer,
      meta: {
        username: s.username,
        created_at: new Date().toISOString(),
        app_version: '2.0.0',
      },
    };
  }

  /**
   * Import is treated as hostile input: strict structural validation first,
   * decryption second (GCM tag enforced), schema validation of the plaintext
   * last. Nothing is trusted or written before all checks pass.
   */
  importBackup(token, userId, confirmPassword, backupObj) {
    const s = this.authorize(token, userId);
    if (typeof confirmPassword !== 'string' || confirmPassword.length === 0 || confirmPassword.length > PASSWORD_MAX) {
      throw new AuthError('CONFIRM_PASSWORD', 'Confirm your password to restore a backup.');
    }
    if (!backupObj || typeof backupObj !== 'object' || Array.isArray(backupObj)) {
      throw new AuthError('MALFORMED', 'Backup must be an object.');
    }
    if (backupObj.format !== 'ses-secure-backup') {
      throw new AuthError(
        'UNSUPPORTED_FORMAT',
        'Not a SES secure backup. Legacy plaintext JSON backups are rejected for security reasons.'
      );
    }
    if (backupObj.format_version !== 2 || backupObj.crypto_version !== C.CRYPTO_VERSION) {
      throw new AuthError('UNSUPPORTED_VERSION', 'Unsupported backup version.');
    }
    if (backupObj.kdf !== C.KDF_NAME) {
      throw new AuthError('UNSUPPORTED_VERSION', 'Unsupported backup KDF.');
    }
    if (!Number.isInteger(backupObj.kdf_iterations) || backupObj.kdf_iterations < C.kekIterations()) {
      throw new AuthError('KDF_PARAMS_INVALID', 'Backup KDF parameters too weak.');
    }
    C.validateContainer(backupObj.wrapped_dek);
    C.validateContainer(backupObj.payload);
    decodeB64OrThrow(backupObj.salt);

    const backupKek = C.deriveKek(confirmPassword, backupObj.salt, backupObj.kdf_iterations);
    let importedDek;
    try {
      importedDek = C.unwrapKey(backupKek, backupObj.wrapped_dek);
    } catch (e) {
      C.zeroBuffer(backupKek);
      throw new AuthError('AUTH_FAILED', 'Backup could not be decrypted (wrong password or tampered file).');
    } finally {
      C.zeroBuffer(backupKek);
    }
    let data;
    try {
      data = C.decryptJson(importedDek, backupObj.payload, 'ses-backup-payload-v2');
    } finally {
      C.zeroBuffer(importedDek);
    }
    validateFinanceData(data);
    // All checks passed — store atomically under THIS session's user only.
    this._writeUserDataEncrypted(s.user_id, data, s.dek);
    return { imported: true, counts: tableCounts(data) };
  }
}

function decodeB64OrThrow(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    throw new AuthError('MALFORMED', 'Invalid backup salt encoding.');
  }
  return Buffer.from(s, 'base64');
}

/* ---------------------------------------------------------------------- *
 * Strict finance-data schema validation (imported content = hostile)     *
 * ---------------------------------------------------------------------- */

const MAX_ROWS = 50000;
const MAX_STR = 500;

function isPlainObject(x) {
  return x && typeof x === 'object' && !Array.isArray(x);
}

function strOk(v, required = false) {
  if (v === undefined || v === null || v === '') return !required;
  return typeof v === 'string' && v.length <= MAX_STR && !/[\u0000-\u001f\u007f]/.test(v);
}

function numOk(v) {
  return v === undefined || v === null || v === '' || (typeof v === 'number' && Number.isFinite(v) && Math.abs(v) < 1e15);
}

function idSet(arr, key, bag) {
  for (const row of arr) {
    if (isPlainObject(row) && typeof row[key] === 'string' && row[key].length <= 64) {
      bag.add(row[key]);
    }
  }
}

/**
 * Validates clients/projects/expenses/payments rows: types, string lengths,
 * numeric ranges, duplicate ids, referential integrity, unexpected props.
 * Returns a normalized copy (only known fields). Throws on anything invalid.
 */
function validateFinanceData(data) {
  if (!isPlainObject(data)) throw new AuthError('BAD_SCHEMA', 'Backup payload must be an object.');
  const tables = ['clients', 'projects', 'expenses', 'payments'];
  for (const t of tables) {
    if (data[t] === undefined) data[t] = [];
    if (!Array.isArray(data[t]) || data[t].length > MAX_ROWS) {
      throw new AuthError('BAD_SCHEMA', `Table '${t}' is missing or malformed.`);
    }
  }
  const out = { version: 1 };

  const checkRows = (rows, name, strFields, numFields, extra) => {
    const seen = new Set();
    const clean = [];
    for (const row of rows) {
      if (!isPlainObject(row)) throw new AuthError('BAD_SCHEMA', `${name}: row must be an object.`);
      const allowed = new Set([...strFields, ...numFields, 'id']);
      for (const k of Object.keys(row)) {
        if (!allowed.has(k)) throw new AuthError('BAD_SCHEMA', `${name}: unexpected property '${k}'.`);
      }
      if (row.id !== undefined) {
        if (!strOk(row.id, true)) throw new AuthError('BAD_SCHEMA', `${name}: bad id.`);
        if (seen.has(row.id)) throw new AuthError('BAD_SCHEMA', `${name}: duplicate id '${row.id}'.`);
        seen.add(row.id);
      }
      for (const f of strFields) {
        if (row[f] !== undefined && !strOk(row[f])) {
          throw new AuthError('BAD_SCHEMA', `${name}.${f}: invalid string value.`);
        }
      }
      for (const f of numFields) {
        if (!numOk(row[f])) {
          throw new AuthError('BAD_SCHEMA', `${name}.${f}: invalid numeric value.`);
        }
      }
      if (extra) extra(row, name);
      clean.push(row);
    }
    return { rows: clean, ids: seen };
  };

  const clients = checkRows(data.clients, 'clients', ['name', 'phone', 'address', 'notes'], []);
  const projects = checkRows(data.projects, 'projects', ['client', 'description', 'status', 'notes'], ['amount', 'paid', 'balance']);
  const expenses = checkRows(data.expenses, 'expenses', ['project', 'category', 'description', 'date'], ['amount']);
  const payments = checkRows(data.payments, 'payments', ['client', 'method', 'reference', 'date'], ['amount']);

  // Referential integrity: project.client / expense.project / payment.client
  const clientNames = clients.ids;
  const projectNames = new Set(projects.rows.map((p) => p.description));
  for (const p of projects.rows) {
    if (p.client && !clientNames.has(String(p.client))) {
      throw new AuthError('BAD_SCHEMA', `projects: unknown client reference '${p.client}'.`);
    }
  }
  for (const e of expenses.rows) {
    if (e.project && !projectNames.has(String(e.project))) {
      throw new AuthError('BAD_SCHEMA', `expenses: unknown project reference '${e.project}'.`);
    }
  }
  for (const pm of payments.rows) {
    if (pm.client && !clientNames.has(String(pm.client))) {
      throw new AuthError('BAD_SCHEMA', `payments: unknown client reference '${pm.client}'.`);
    }
  }

  out.clients = clients.rows;
  out.projects = projects.rows;
  out.expenses = expenses.rows;
  out.payments = payments.rows;
  return out;
}

function tableCounts(data) {
  return {
    clients: data.clients.length,
    projects: data.projects.length,
    expenses: data.expenses.length,
    payments: data.payments.length,
  };
}

module.exports = { AuthManager, AuthError, validateUsernameShape, validatePasswordShape, unameKey };
