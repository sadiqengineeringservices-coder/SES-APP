export interface Client { id: string; name: string; phone?: string; address?: string; notes?: string; }
export interface Project { id: string; client: string; description?: string; status?: string; amount?: number; paid?: number; balance?: number; notes?: string; }
export interface Expense { id: string; date: string; project: string; category?: string; description?: string; amount?: number; }
export interface Payment { id: string; date: string; client: string; method?: string; reference?: string; amount?: number; }

/** The complete per-user financial dataset (encrypted at rest as ONE payload). */
export interface FinanceData {
  version: number;
  clients: Client[];
  projects: Project[];
  expenses: Expense[];
  payments: Payment[];
}

export const EMPTY_FINANCE: FinanceData = {
  version: 1,
  clients: [],
  projects: [],
  expenses: [],
  payments: [],
};

export interface SessionInfo {
  user_id: string;
  username: string;
  display_name: string;
}

export interface IpcResult<T = unknown> {
  ok: boolean;
  code?: string;
  message?: string;
  retryAfterMs?: number;
  canceled?: boolean;
}
