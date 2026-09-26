'use strict';
/**
 * electron/export.js — human-readable export (main process only).
 *
 * Policy:
 *  - Excel/CSV export is an EXPLICIT user action, never automatic.
 *  - Output goes ONLY to a file the user picks through the native Save dialog;
 *    if the user cancels, nothing is written anywhere.
 *  - No application-side copy is retained: no staging files, no temp copies,
 *    no cache of exported content.
 *  - The renderer cannot choose the destination path (dialog-selected only)
 *    and cannot supply arbitrary file names beyond what we sanitize here.
 *  - Automatic plaintext JSON backups are REMOVED by design; secure encrypted
 *    backups live in ipc.js (ses:create-backup / ses:import-backup).
 */

const fs = require('fs');
const path = require('path');
const { SecurityError } = require('./crypto');
const S = require('./storage');

let XLSX = null;
function xlsx() {
  if (!XLSX) {
    try {
      // eslint-disable-next-line global-require
      XLSX = require('xlsx');
    } catch (e) {
      throw new SecurityError('NO_XLSX', 'Excel export library not installed.');
    }
  }
  return XLSX;
}

const SHEETS = [
  ['clients', 'Clients', ['name', 'phone', 'address', 'notes']],
  ['projects', 'Projects', ['client', 'description', 'status', 'amount', 'paid', 'balance', 'notes']],
  ['expenses', 'Expenses', ['date', 'project', 'category', 'description', 'amount']],
  ['payments', 'Payments', ['date', 'client', 'method', 'reference', 'amount']],
];

/** Build workbook buffers IN MEMORY from validated session data. */
function buildWorkbook(tables) {
  const wb = xlsx().utils.book_new();
  for (const [key, sheetName] of SHEETS) {
    const rows = Array.isArray(tables && tables[key]) ? tables[key] : [];
    const ws = xlsx().utils.json_to_sheet(rows.length ? rows : []);
    xlsx().utils.book_append_sheet(wb, ws, sheetName);
  }
  return xlsx().write(wb, { type: 'buffer', bookType: 'xlsx' });
}

/**
 * Write exported bytes to a user-chosen absolute path (from the native
 * Save dialog). The base name is sanitized; directories come from the OS
 * dialog, not the renderer. Refuses symlinked destinations.
 */
function writeToChosenPath(chosenPath, buf, ext) {
  if (typeof chosenPath !== 'string' || !path.isAbsolute(chosenPath)) {
    throw new SecurityError('INVALID_PATH', 'Export destination must be an absolute path from the save dialog.');
  }
  let dir;
  let base;
  try {
    dir = path.dirname(chosenPath);
    base = path.basename(chosenPath);
  } catch (e) {
    throw new SecurityError('INVALID_PATH', 'Unusable export path.');
  }
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    throw new SecurityError('INVALID_PATH', 'Export destination directory does not exist.');
  }
  // Sanitize just the file name portion; re-append expected extension.
  let safeBase;
  try {
    safeBase = S.validateName(base.replace(/\.[^.]+$/, ''), 'file name', 80);
  } catch (e) {
    safeBase = 'SES_Export';
  }
  const target = path.join(dir, `${safeBase}${ext}`);
  try {
    const st = fs.lstatSync(target);
    if (st.isSymbolicLink()) {
      throw new SecurityError('SYMLINK_REJECTED', 'Refusing to write through a symbolic link.');
    }
  } catch (e) {
    if (e instanceof SecurityError) throw e;
    /* file does not exist yet — fine */
  }
  fs.writeFileSync(target, buf, { mode: 0o600 });
  return target;
}

module.exports = {
  buildWorkbook,
  writeToChosenPath,
};
