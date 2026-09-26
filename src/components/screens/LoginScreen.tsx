import React, { useEffect, useState } from 'react';
import { register, login, listUsers } from '../../lib/desktop';
import { sessionStore } from '../../store/session';

export default function LoginScreen() {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [users, setUsers] = useState<{ username: string }[]>([]);

  useEffect(() => {
    listUsers().then((r) => r.ok && setUsers(r.users)).catch(() => undefined);
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === 'register') {
        if (password !== confirm) throw new Error('Passwords do not match.');
        const r = await register(username, password);
        if (!r.ok) throw new Error(r.message || 'Registration failed.');
        setNotice('Account created. Please sign in.');
        setMode('login');
        setPassword(''); setConfirm('');
      } else {
        const r = await login(username, password);
        if (!r.ok) {
          if (r.retryAfterMs) setTimeout(() => setBusy(false), Math.min(r.retryAfterMs, 30000));
          throw new Error(r.message || 'Sign-in failed.');
        }
        // Binding a session wipes any previous user's in-memory state first.
        sessionStore.setSession(r.token, {
          user_id: r.user_id, username: r.username, display_name: r.display_name,
        });
      }
    } catch (err: any) {
      setError(err.message || String(err));
    } finally {
      setBusy(false);
      // Never keep the password in component state after an attempt.
      setPassword(''); setConfirm('');
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 text-slate-100 p-6">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 bg-slate-800 p-6 rounded-xl shadow-lg">
        <h1 className="text-xl font-semibold">SES Offline Workshop</h1>
        <p className="text-xs text-slate-400">100% offline · data encrypted per user on this PC only</p>
        {users.length > 0 && mode === 'login' && (
          <div className="text-xs text-slate-400">Accounts on this PC: {users.map((u) => u.username).join(', ')}</div>
        )}
        <input className="w-full p-2 rounded bg-slate-700" placeholder="Username" value={username}
               onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        <input className="w-full p-2 rounded bg-slate-700" placeholder="Password" type="password" value={password}
               onChange={(e) => setPassword(e.target.value)} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} />
        {mode === 'register' && (
          <input className="w-full p-2 rounded bg-slate-700" placeholder="Confirm password" type="password" value={confirm}
                 onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
        )}
        {notice && <div className="text-sm text-emerald-400">{notice}</div>}
        {error && <div role="alert" className="text-sm text-red-400 whitespace-pre-wrap">{error}</div>}
        <button disabled={busy} className="w-full py-2 rounded bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50">
          {busy ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
        </button>
        <button type="button" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null); }}
                className="w-full text-sm text-indigo-300 underline">
          {mode === 'login' ? 'Create a new local account' : 'Back to sign in'}
        </button>
        <p className="text-[11px] text-slate-500 leading-snug">
          Your password is the only key to your data. It is never stored anywhere. If you lose it,
          your encrypted data cannot be recovered — there is no server and no back door.
        </p>
      </form>
    </div>
  );
}
