'use strict';
/**
 * preload.js — the ENTIRE privileged surface exposed to the renderer.
 *
 * Rules enforced here (and again, independently, in the main process):
 *  - No fs / crypto / child_process / shell objects are ever exposed.
 *  - No generic readFile(path)/writeFile(path) API exists.
 *  - Every call is a narrow, named operation; the session token returned by
 *    login() must be passed with each authenticated call. The main process
 *    re-derives the trusted user id from that token and REJECTS any call
 *    whose userId argument does not match the session (IDOR defence).
 *  - Plaintext auto-backup channels (saveJsonAs/openJson/getDataFolder/
 *    chooseDataFolder/saveEntry) were removed on purpose: they stored
 *    financial data unencrypted and let the renderer pick paths.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktopAPI', {
  // ---- authentication -------------------------------------------------
  register: (username, password, displayName) =>
    ipcRenderer.invoke('ses:register', { username, password, displayName }),
  login: (username, password) =>
    ipcRenderer.invoke('ses:login', { username, password }),
  logout: (token) => ipcRenderer.invoke('ses:logout', { token }),
  sessionInfo: (token) => ipcRenderer.invoke('ses:session', { token }),
  listUsers: () => ipcRenderer.invoke('ses:list-users'),
  changePassword: (token, currentPassword, newPassword) =>
    ipcRenderer.invoke('ses:change-password', { token, currentPassword, newPassword }),

  // ---- encrypted per-user finance data --------------------------------
  loadData: (token, userId) => ipcRenderer.invoke('ses:load-data', { token, userId }),
  saveData: (token, userId, data) => ipcRenderer.invoke('ses:save-data', { token, userId, data }),

  // ---- secure (encrypted) backup / restore ----------------------------
  createSecureBackup: (token, userId, password) =>
    ipcRenderer.invoke('ses:create-backup', { token, userId, password }),
  importSecureBackup: (token, userId, password) =>
    ipcRenderer.invoke('ses:import-backup', { token, userId, password }),

  // ---- explicit, human-readable Excel export (plaintext by nature) ----
  exportExcel: (token, userId) =>
    ipcRenderer.invoke('ses:export-excel', { token, userId }),
});
