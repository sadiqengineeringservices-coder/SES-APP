'use strict';
/**
 * electron/ipc.js — the ONLY bridge between renderer and privileged code.
 *
 * Design:
 *  - No generic readFile/writeFile/shell IPC exists. Every channel is a narrow,
 *    session-bound operation. The renderer never chooses paths or key material.
 *  - `userId` is ALWAYS taken from the authenticated main-process session;
 *    any userId argument supplied by the renderer is cross-checked against the
 *    session (IDOR defence) — mismatches are rejected fail-closed.
 *  - Arguments are type/size validated before use.
 *  - Errors returned to the renderer carry only safe codes/messages; nothing
 *    from registry internals, keys, or decrypted state is ever serialized out.
 */

const path = require('path');
const fs = require('fs');
const { dialog } = require('electron');
const { AuthManager, AuthError } = require('./auth');
const { SecurityError, MAX_CONTAINER_JSON } = require('./crypto');
const S = require('./storage');
const X = require('./export');

const MAX_ARG_TABLES = 8 * 1024 * 1024; // JSON size ceiling for renderer payloads

function safeError(e) {
  const code =
    e instanceof AuthError || e instanceof SecurityError ? e.code : 'INTERNAL';
  // Never leak stack traces / internals / file contents into IPC responses.
  const message =
    e instanceof AuthError || e instanceof SecurityError
      ? e.message
      : 'An unexpected error occurred.';
  return { ok: false, code, message, retryAfterMs: e.retryAfterMs };
}

function isPlainObject(x) {
  return x && typeof x === 'object' && !Array.isArray(x);
}

function boundedJson(x, maxBytes) {
  let json;
  try {
    json = JSON.stringify(x);
  } catch (e) {
    return null;
  }
  if (!json || Buffer.byteLength(json) > maxBytes) return null;
  return json;
}

function registerIpcHandlers(ipcMain, opts = {}) {
  const auth = opts.auth || new AuthManager();

  /* ------------------------- authentication --------------------------- */

  ipcMain.handle('ses:register', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      const r = auth.register(args.username, args.password, args.displayName);
      return { ok: true, user_id: r.user_id, username: r.username };
    } catch (e) {
      return safeError(e);
    }
  });

  ipcMain.handle('ses:login', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      const s = auth.login(args.username, args.password);
      return { ok: true, ...s };
    } catch (e) {
      return safeError(e);
    }
  });

  ipcMain.handle('ses:logout', async (_ev, args) => {
    try {
      const token = isPlainObject(args) ? args.token : null;
      return { ok: true, ...auth.logout(token) };
    } catch (e) {
      return safeError(e);
    }
  });

  ipcMain.handle('ses:session', async (_ev, args) => {
    try {
      const token = isPlainObject(args) ? args.token : null;
      return { ok: true, session: auth.getSessionInfo(token) };
    } catch (e) {
      return safeError(e);
    }
  });

  ipcMain.handle('ses:list-users', async () => {
    // Public registry info only (ids + usernames). No secrets, ever.
    return { ok: true, users: auth.listUsernames() };
  });

  ipcMain.handle('ses:change-password', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      return { ok: true, ...auth.changePassword(args.token, args.currentPassword, args.newPassword) };
    } catch (e) {
      return safeError(e);
    }
  });

  /* ----------------------------- data I/O ----------------------------- */

  ipcMain.handle('ses:load-data', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      const data = auth.loadData(args.token, args.userId);
      return { ok: true, data };
    } catch (e) {
      return safeError(e);
    }
  });

  ipcMain.handle('ses:save-data', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      if (!boundedJson(args.data, MAX_ARG_TABLES)) {
        throw new SecurityError('TOO_LARGE', 'Payload too large.');
      }
      const r = await auth.saveData(args.token, args.userId, args.data);
      return { ok: true, ...r };
    } catch (e) {
      return safeError(e);
    }
  });

  /* ------------------------ secure backup files ----------------------- */

  ipcMain.handle('ses:create-backup', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      const { canceled, filePaths } = await dialog.showSaveDialog({
        title: 'Encrypted backup — save as',
        defaultPath: `SES_SecureBackup_${new Date().toISOString().slice(0, 10)}.sesb.json`,
        filters: [{ name: 'SES Secure Backup', extensions: ['sesb.json', 'json'] }],
      });
      if (canceled || !filePaths || !filePaths[0]) return { ok: true, canceled: true };
      const backup = auth.createBackup(args.token, args.userId, args.password);
      const target = X.writeToChosenPath(filePaths[0], JSON.stringify(backup, null, 2), '');
      return { ok: true, path: target, encrypted: true };
    } catch (e) {
      return safeError(e);
    }
  });

  ipcMain.handle('ses:import-backup', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      const { canceled, filePaths } = await dialog.showOpenDialog({
        title: 'Restore encrypted backup',
        filters: [{ name: 'SES Secure Backup', extensions: ['sesb.json', 'json'] }],
        properties: ['openFile'],
      });
      if (canceled || !filePaths || !filePaths[0]) return { ok: true, canceled: true };
      const chosen = filePaths[0];
      // Size-capped, symlink-safe read of the user-picked file.
      const obj = S.readJsonFileCapped(chosen, MAX_CONTAINER_JSON);
      const r = auth.importBackup(args.token, args.userId, args.password, obj);
      return { ok: true, ...r };
    } catch (e) {
      return safeError(e);
    }
  });

  /* ------------------- human-readable Excel export -------------------- */

  ipcMain.handle('ses:export-excel', async (_ev, args) => {
    try {
      if (!isPlainObject(args)) throw new AuthError('INVALID_INPUT', 'Bad request.');
      const info = auth.getSessionInfo(args.token);
      if (isPlainObject(args) && args.userId && args.userId !== info.user_id) {
        throw new AuthError('FORBIDDEN', 'Export targets a different user than the session.');
      }
      const data = auth.loadData(args.token, info.user_id);
      const buf = X.buildWorkbook(data);
      const { canceled, filePaths } = await dialog.showSaveDialog({
        title: 'Export to Excel (PLAINTEXT — anyone with the file can read it)',
        message: 'Warning: this file is NOT encrypted. Store it safely.',
        defaultPath: `SES_Export_${info.username}_${new Date().toISOString().slice(0, 10)}.xlsx`,
        filters: [{ name: 'Excel Workbook', extensions: ['xlsx'] }],
      });
      if (canceled || !filePaths || !filePaths[0]) return { ok: true, canceled: true };
      const target = X.writeToChosenPath(filePaths[0], buf, '.xlsx');
      return { ok: true, path: target, warning: 'Exported file is plaintext. No application copy was retained.' };
    } catch (e) {
      return safeError(e);
    }
  });

  /* --------------------- legacy channels removed ---------------------- *
   * 'ses:get-data-folder', 'ses:choose-data-folder', 'ses:save-json-as',
   * 'ses:open-json' and 'save-entry' intentionally DO NOT exist anymore:
   * they wrote/read plaintext financial data and let the renderer pick
   * paths. Data now lives only in the private per-user encrypted store.
   */

  return { auth };
}

module.exports = { registerIpcHandlers, safeError };
