/*
 * React Query hooks — the single source of truth for server state.
 *
 * Queries cache + dedupe + refetch; mutations invalidate the affected caches so
 * the UI stays consistent without manual refetching. Components never call the
 * API client directly; they use these hooks.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { DecisionMode } from "@/lib/types";

export const keys = {
  alerts: (f?: object) => ["alerts", f] as const,
  alert: (id: string) => ["alert", id] as const,
  events: (f?: object) => ["events", f] as const,
  actions: (status?: string) => ["actions", status] as const,
  action: (id: string) => ["action", id] as const,
  reports: () => ["reports"] as const,
  report: (id: string) => ["report", id] as const,
  audit: (f?: object) => ["audit", f] as const,
  rules: () => ["rules"] as const,
};

// ── Alerts ──
export const useAlerts = (filters?: { severity?: string; status?: string; limit?: number }) =>
  useQuery({ queryKey: keys.alerts(filters), queryFn: () => api.listAlerts(filters) });

export const useAlert = (id: string) =>
  useQuery({ queryKey: keys.alert(id), queryFn: () => api.getAlert(id), enabled: !!id });

// ── Events ──
export const useEvents = (filters?: { severity?: string; limit?: number }) =>
  useQuery({ queryKey: keys.events(filters), queryFn: () => api.listEvents(filters) });

// ── Approval queue ──
export const useActions = (status?: string) =>
  useQuery({ queryKey: keys.actions(status), queryFn: () => api.listActions(status) });

export const useActionDetail = (id: string) =>
  useQuery({ queryKey: keys.action(id), queryFn: () => api.getAction(id), enabled: !!id });

export function useReviewAction() {
  const qc = useQueryClient();
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["actions"] });
    qc.invalidateQueries({ queryKey: ["action"] });
  };
  return {
    approve: useMutation({ mutationFn: (v: { id: string; notes?: string }) => api.approve(v.id, v.notes), onSuccess: invalidate }),
    deny: useMutation({ mutationFn: (v: { id: string; notes?: string }) => api.deny(v.id, v.notes), onSuccess: invalidate }),
    execute: useMutation({ mutationFn: (id: string) => api.execute(id), onSuccess: invalidate }),
    rollback: useMutation({ mutationFn: (id: string) => api.rollback(id), onSuccess: invalidate }),
  };
}

export function useAddComment(actionId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: string) => api.addComment(actionId, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.action(actionId) }),
  });
}

// ── Analysis & decision ──
export function useAnalyzeAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { id: string; createActions?: boolean }) => api.analyzeAlert(v.id, v.createActions),
    onSuccess: (_d, v) => qc.invalidateQueries({ queryKey: keys.alert(v.id) }),
  });
}

export function useDecideAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { id: string; mode?: DecisionMode; createActions?: boolean }) =>
      api.decideAlert(v.id, v.mode, v.createActions),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["actions"] }),
  });
}

export const useRunDetection = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (lookback?: number) => api.runDetection(lookback),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alerts"] }),
  });
};

// ── Reports ──
export const useReports = () =>
  useQuery({ queryKey: keys.reports(), queryFn: () => api.listReports() });

export const useReport = (id: string) =>
  useQuery({ queryKey: keys.report(id), queryFn: () => api.getReport(id), enabled: !!id });

export function useGenerateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (alertId: string) => api.generateReportForAlert(alertId),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.reports() }),
  });
}

// ── Audit & rules ──
export const useAuditLogs = (filters?: { action?: string; limit?: number }) =>
  useQuery({ queryKey: keys.audit(filters), queryFn: () => api.auditLogs(filters) });

export const useRules = () =>
  useQuery({ queryKey: keys.rules(), queryFn: () => api.listRules() });

// ── Attack simulator ──
export const useScenarios = () =>
  useQuery({ queryKey: ["scenarios"], queryFn: api.listScenarios, staleTime: Infinity });

export function useRunScenario() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.runScenario(id),
    // A run creates events and alerts, so refresh everything the console shows.
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["alerts"] });
      qc.invalidateQueries({ queryKey: ["events"] });
      qc.invalidateQueries({ queryKey: ["actions"] });
    },
  });
}
