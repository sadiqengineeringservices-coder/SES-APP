import React, { useEffect, useRef, useState } from 'react';
import { sessionStore } from '../../store/session';
import { loadCurrentUserData, saveCurrentUserData, logout, createCurrentUserBackup, importCurrentUserBackup, exportCurrentUserExcel } from '../../lib/desktop';
import { FinanceData, EMPTY_FINANCE } from '../../types';

/**
 * Functional shell preserving the original four-table workflow
 * (Clients / Projects / Expenses / Payments) plus secure backup, restore,
 * explicit Excel export, password change and logout. Auto-save is debounced
 * and always bound to the CURRENT session — late saves after logout are
 * rejected by the main process.
 */
export default function FinanceApp() {
  const [data, setData] = useState<FinanceData>(EMPTY_FINANCE);
  const [status, setStatus] = useState<string>('Loading…');
  const [tab, setTab] = useState<'clients' | 'projects' | 'expenses' | 'payments'>('clients');
  const [pwModal, setPwModal] = useState<null | 'backup' | 'restore'>(null);
  const pwInput = useRef<HTMLInputElement>(null);
  const { session } = sessionStore.snapshot();
  const myUserId = session?.user_id;
  const mountedRef = useRef(true);
  const saveTimer = useRef<number | undefined>(undefined);
  const loadedRef = useRef(false);

  useEffect(() => {
    mountedRef.current = true;
    (async () => {
      try {
        const d = await loadCurrentUserData();
        if (mountedRef.current && sessionStore.snapshot().session?.user_id === myUserId) {
          setData(d);
          loadedRef.current = true;
          setStatus('Ready — everything is encrypted locally.');
        }
      } catch (e: any) {
        if (mountedRef.current) setStatus(`Could not load data: ${e.message}`);
      }
    })();
    return () => { mountedRef.current = false; };
  }, [myUserId]);

  function update(next: FinanceData) {
    setData(next);
    window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(async () => {
      if (!loadedRef.current || !mountedRef.current) return;
      try {
        await saveCurrentUserData(next);
        setStatus(`Saved (encrypted) ${new Date().toLocaleTimeString()}`);
      } catch (e: any) {
        setStatus(`Save refused: ${e.message}`);
      }
    }, 600);
  }

  function addRow(table: keyof Omit<FinanceData, 'version'>, row: Record<string, string | number>) {
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    update({ ...data, [table]: [...(data[table] as any[]), { id, ...row }] } as FinanceData);
  }

  async function doBackup() {
    const pw = pwInput.current?.value || '';
    setPwModal(null);
    const r = await createCurrentUserBackup(pw);
    setStatus(r.canceled ? 'Backup canceled.' : r.ok ? `Encrypted backup written to ${r.path}` : `Backup failed: ${r.message}`);
  }
  async function doRestore() {
    const pw = pwInput.current?.value || '';
    setPwModal(null);
    const r = await importCurrentUserBackup(pw);
    if (r.ok && !r.canceled) {
      setData(await loadCurrentUserData());
      setStatus(`Restored: ${r.counts.clients} clients, ${r.counts.projects} projects, ${r.counts.expenses} expenses, ${r.counts.payments} payments.`);
    } else {
      setStatus(r.canceled ? 'Restore canceled.' : `Restore failed: ${r.message}`);
    }
  }

  const cols: Record<string, string[]> = {
    clients: ['name', 'phone', 'address'],
    projects: ['client', 'description', 'amount'],
    expenses: ['date', 'project', 'description', 'amount'],
    payments: ['date', 'client', 'method', 'amount'],
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      <header className="flex items-center justify-between mb-4">
        <h1 className="text-lg font-semibold">SES Offline Workshop — {session?.display_name}</h1>
        <div className="space-x-2">
          <button className="px-3 py-1 rounded bg-slate-700" onClick={() => exportCurrentUserExcel().then((r) => setStatus(r.canceled ? 'Export canceled.' : r.ok ? `Exported (plaintext!) to ${r.path}` : `Export failed: ${r.message}`))}>
            Export Excel…
          </button>
          <button className="px-3 py-1 rounded bg-slate-700" onClick={() => { setPwModal('backup'); }}>Secure Backup…</button>
          <button className="px-3 py-1 rounded bg-slate-700" onClick={() => { setPwModal('restore'); }}>Restore Backup…</button>
          <button className="px-3 py-1 rounded bg-red-700" onClick={async () => { loadedRef.current = false; await logout(); }}>Log out</button>
        </div>
      </header>
      <nav className="space-x-2 mb-3">
        {(['clients', 'projects', 'expenses', 'payments'] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
                  className={`px-3 py-1 rounded capitalize ${tab === t ? 'bg-indigo-600' : 'bg-slate-800'}`}>{t}</button>
        ))}
      </nav>
      <table className="w-full text-sm border border-slate-700">
        <thead><tr>{cols[tab].map((c) => <th key={c} className="text-left p-2 border-b border-slate-700 capitalize">{c}</th>)}</tr></thead>
        <tbody>
          {(data[tab] as any[]).map((row) => (
            <tr key={row.id}>{cols[tab].map((c) => <td key={c} className="p-2 border-b border-slate-800">{String(row[c] ?? '')}</td>)}</tr>
          ))}
          {(data[tab] as any[]).length === 0 && (
            <tr><td colSpan={cols[tab].length} className="p-3 text-slate-500">No records yet.</td></tr>
          )}
        </tbody>
      </table>
      <QuickAdd fields={cols[tab]} onAdd={(vals) => addRow(tab, vals)} />
      <p className="mt-4 text-xs text-slate-400">{status}</p>
      {pwModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center">
          <div className="bg-slate-800 p-5 rounded-xl w-80 space-y-3">
            <h2 className="font-medium">{pwModal === 'backup' ? 'Create encrypted backup' : 'Restore encrypted backup'}</h2>
            <p className="text-xs text-slate-400">Confirm your password. Backups are AES-256-GCM encrypted and readable only with your credentials.</p>
            <input ref={pwInput} type="password" className="w-full p-2 rounded bg-slate-700" placeholder="Your password" autoComplete="current-password" />
            <div className="flex gap-2">
              <button className="flex-1 py-1 rounded bg-indigo-600" onClick={pwModal === 'backup' ? doBackup : doRestore}>Continue</button>
              <button className="flex-1 py-1 rounded bg-slate-700" onClick={() => setPwModal(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function QuickAdd({ fields, onAdd }: { fields: string[]; onAdd: (v: Record<string, string | number>) => void }) {
  const [vals, setVals] = useState<Record<string, string>>({});
  return (
    <form className="mt-3 flex flex-wrap gap-2 items-center" onSubmit={(e) => { e.preventDefault(); const out: Record<string, string | number> = {}; for (const f of fields) { const v = (vals[f] || '').trim(); if (!v) continue; out[f] = ['amount', 'paid', 'balance'].includes(f) ? Number(v) : v; } if (Object.keys(out).some((k) => ['amount', 'paid', 'balance'].includes(k) && Number.isNaN(Number(out[k as any]))) ) return; onAdd(out); setVals({}); }}>
      {fields.map((f) => (
        <input key={f} className="p-2 rounded bg-slate-800 w-40" placeholder={f} value={vals[f] || ''}
               onChange={(e) => setVals({ ...vals, [f]: e.target.value })} />
      ))}
      <button className="px-3 py-1 rounded bg-emerald-700">Add</button>
    </form>
  );
}
