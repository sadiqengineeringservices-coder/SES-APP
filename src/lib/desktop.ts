/**
 * Thin typed wrapper over window.desktopAPI. Every call returns the main
 * process verdict; on authorization/crypto failure the main process refuses
 * (fail-closed) and we surface a safe message. No crypto happens here.
 */
import { FinanceData, EMPTY_FINANCE } from '../types';
import { sessionStore } from '../store/session';

function api() {
  if (!window.desktopAPI) {
    throw new Error('Desktop bridge unavailable. Use the packaged desktop app.');
  }
  return window.desktopAPI;
}

export async function register(username: string, password: string, displayName?: string) {
  return api().register(username, password, displayName);
}
export async function login(username: string, password: string) {
  return api().login(username, password);
}
export async function logout() {
  try {
    const { token } = sessionStore.require();
    await api().logout(token);
  } catch { /* already signed out */ }
  sessionStore.clear();
}
export async function loadCurrentUserData(): Promise<FinanceData> {
  const { token, userId } = sessionStore.require();
  const r = await api().loadData(token, userId);
  if (!r.ok) { handleAuthFailure(r); throw new Error(r.message || 'Unable to load data.'); }
  return r.data as FinanceData;
}
export async function saveCurrentUserData(data: FinanceData) {
  const { token, userId } = sessionStore.require();
  const r = await api().saveData(token, userId, data);
  if (!r.ok) { handleAuthFailure(r); throw new Error(r.message || 'Save failed.'); }
  sessionStore.setData(data);
}
export async function createCurrentUserBackup(password: string) {
  const { token, userId } = sessionStore.require();
  return api().createSecureBackup(token, userId, password);
}
export async function importCurrentUserBackup(password: string) {
  const { token, userId } = sessionStore.require();
  const r = await api().importSecureBackup(token, userId, password);
  if (r.ok && !r.canceled) {
    const fresh = await loadCurrentUserData();
    sessionStore.setData(fresh);
  }
  return r;
}
export async function exportCurrentUserExcel() {
  const { token, userId } = sessionStore.require();
  return api().exportExcel(token, userId);
}
export async function changePassword(current: string, next: string) {
  const { token } = sessionStore.require();
  return api().changePassword(token, current, next);
}
export async function listUsers() {
  return api().listUsers();
}

/** If the main process says our session is gone, wipe local state instantly. */
function handleAuthFailure(r: { code?: string }) {
  if (r.code === 'NO_SESSION' || r.code === 'SESSION_EXPIRED' || r.code === 'STALE_SESSION') {
    sessionStore.clear();
  }
}

export { EMPTY_FINANCE };
