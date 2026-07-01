/*
 * Typed API client for the AADA backend.
 *
 * One thin wrapper around fetch handles the base URL, JSON, the JWT bearer
 * header (read from the Zustand store), and error normalization. Every endpoint
 * is a typed method, so callers and React Query hooks get full inference.
 */
import { useAppStore } from "@/store/appStore";
import type {
  Action, ActionDetail, AIAnalysis, Alert, AlertList, AuditLog, Comment,
  CurrentUser, Decision, DecisionMode, ExecutionResult, IncidentReport,
  ReportListItem, RuleInfo, SecurityEvent, Token,
} from "@/lib/types";

const BASE = import.meta.env.VITE_API_BASE || "/api/v1";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type Opts = { method?: string; body?: unknown; params?: Record<string, unknown> };

async function request<T>(path: string, opts: Opts = {}): Promise<T> {
  const { method = "GET", body, params } = opts;
  let url = `${BASE}${path}`;
  if (params) {
    const q = new URLSearchParams(
      Object.entries(params)
        .filter(([, v]) => v !== undefined && v !== null && v !== "")
        .map(([k, v]) => [k, String(v)]),
    ).toString();
    if (q) url += `?${q}`;
  }
  const token = useAppStore.getState().token;
  const res = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) useAppStore.getState().setToken(null);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail ?? detail; } catch { /* noop */ }
    throw new ApiError(res.status, detail);
  }
  return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
}

export const api = {
  // Auth
  login: (email: string, password: string) => {
    const form = new URLSearchParams({ username: email, password });
    return fetch(`${BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    }).then((r) => {
      if (!r.ok) throw new ApiError(r.status, "Login failed");
      return r.json() as Promise<Token>;
    });
  },
  me: () => request<CurrentUser>("/auth/me"),
  refresh: (refresh_token: string) =>
    request<Token>("/auth/refresh", { method: "POST", params: { refresh_token } }),

  // Alerts
  listAlerts: (p?: { severity?: string; status?: string; limit?: number; offset?: number }) =>
    request<AlertList>("/alerts", { params: p }),
  getAlert: (id: string) => request<Alert>(`/alerts/${id}`),

  // Events
  listEvents: (p?: { source?: string; severity?: string; limit?: number }) =>
    request<SecurityEvent[]>("/events", { params: p }),

  // Detection
  runDetection: (lookback_minutes = 60) =>
    request<{ events_analyzed: number; detections: number; alerts_created: number }>(
      "/detection/run", { method: "POST", body: { lookback_minutes } }),
  listRules: () => request<RuleInfo[]>("/detection/rules"),

  // AI analyst
  analyzeAlert: (id: string, create_actions = false) =>
    request<AIAnalysis>(`/analyst/alerts/${id}/analyze`, { method: "POST", params: { create_actions } }),

  // Decision engine
  decideAlert: (id: string, mode?: DecisionMode, create_actions = false) =>
    request<Decision>(`/decision/alerts/${id}/decide`, { method: "POST", params: { mode, create_actions } }),

  // Response / approval queue
  listActions: (status?: string) => request<Action[]>("/response/actions", { params: { status } }),
  getAction: (id: string) => request<ActionDetail>(`/response/actions/${id}`),
  approve: (id: string, notes?: string) =>
    request<Action>(`/response/actions/${id}/approve`, { method: "POST", body: { notes } }),
  deny: (id: string, notes?: string) =>
    request<Action>(`/response/actions/${id}/deny`, { method: "POST", body: { notes } }),
  execute: (id: string) => request<ExecutionResult>(`/response/actions/${id}/execute`, { method: "POST" }),
  rollback: (id: string) => request<ExecutionResult>(`/response/actions/${id}/rollback`, { method: "POST" }),
  listComments: (id: string) => request<Comment[]>(`/response/actions/${id}/comments`),
  addComment: (id: string, body: string) =>
    request<Comment>(`/response/actions/${id}/comments`, { method: "POST", body: { body } }),

  // Reports
  listReports: () => request<ReportListItem[]>("/reports"),
  getReport: (id: string) => request<IncidentReport>(`/reports/${id}`),
  generateReportForAlert: (alertId: string) =>
    request<IncidentReport>(`/reports/alerts/${alertId}/generate`, { method: "POST" }),
  reportPdfUrl: (id: string) => `${BASE}/reports/${id}/export.pdf`,
  reportJsonUrl: (id: string) => `${BASE}/reports/${id}/export.json`,

  // Audit
  auditLogs: (p?: { action?: string; resource_type?: string; limit?: number }) =>
    request<AuditLog[]>("/audit/logs", { params: p }),

  // Knowledge (RAG)
  knowledgeQuery: (query: string, top_k = 5) =>
    request<{ query: string; results: { score: number; title: string; citation: string; text: string }[] }>(
      "/knowledge/query", { method: "POST", body: { query, top_k } }),
};
