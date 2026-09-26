/**
 * Renderer-side session + data holder.
 *
 * IMPORTANT SECURITY NOTES:
 *  - This module holds ONLY a session TOKEN and display info. All actual
 *    authentication, keys and storage live in the Electron MAIN process.
 *    Even if this state were tampered with, every IPC call is re-authorized
 *    server-side(main-side) against the token; forged user IDs are rejected.
 *  - resetForUserSwitch() MUST be called on logout/login so no previous
 *    user's decrypted finance data can ever flash or persist in memory.
 */
import { FinanceData, SessionInfo, EMPTY_FINANCE } from '../types';

type Listener = () => void;

interface Holder {
  token: string | null;
  session: SessionInfo | null;
  data: FinanceData;
  dirty: boolean;
}

let h: Holder = { token: null, session: null, data: EMPTY_FINANCE, dirty: false };
const listeners = new Set<Listener>();

function notify() { for (const l of listeners) l(); }

export const sessionStore = {
  subscribe(l: Listener) { listeners.add(l); return () => listeners.delete(l); },
  snapshot() { return h; },

  setSession(token: string, session: SessionInfo) {
    // Binding a new session ALWAYS wipes any previous user's state first.
    h = { token, session, data: EMPTY_FINANCE, dirty: false };
    notify();
  },

  setData(data: FinanceData) {
    h = { ...h, data, dirty: false };
    notify();
  },

  markDirty() { h = { ...h, dirty: true }; notify(); },

  clear() {
    // Logout: drop token, session identity AND decrypted data references.
    h = { token: null, session: null, data: EMPTY_FINANCE, dirty: false };
    notify();
  },

  require(): { token: string; userId: string } {
    if (!h.token || !h.session) throw new Error('Not authenticated.');
    return { token: h.token, userId: h.session.user_id };
  },
};
