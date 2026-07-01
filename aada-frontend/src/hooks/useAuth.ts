/*
 * Auth hooks.
 *
 * `useMe` fetches the current user (the token is the source of truth — if it
 * decodes server-side, you're authenticated). `useLogin`/`logout` manage the
 * token in the Zustand store, which the API client reads for every request.
 * `usePermissions` mirrors the backend permission map so the UI can hide/disable
 * controls a role isn't allowed to use (defense in depth — the server still
 * enforces it).
 */
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { useAppStore } from "@/store/appStore";
import type { RoleName } from "@/lib/types";

export function useMe() {
  const token = useAppStore((s) => s.token);
  return useQuery({
    queryKey: ["me", token],
    queryFn: () => api.me(),
    enabled: !!token,
    staleTime: 5 * 60_000,
    retry: false,
  });
}

export function useLogin() {
  const setToken = useAppStore((s) => s.setToken);
  const qc = useQueryClient();
  return async (email: string, password: string) => {
    const tok = await api.login(email, password);
    setToken(tok.access_token);
    localStorage.setItem("aada_refresh", tok.refresh_token);
    await qc.invalidateQueries();
  };
}

export function useLogout() {
  const setToken = useAppStore((s) => s.setToken);
  const qc = useQueryClient();
  return () => {
    setToken(null);
    localStorage.removeItem("aada_refresh");
    qc.clear();
  };
}

// Client-side mirror of the backend RBAC map (UX only; server is authoritative).
const PERMS: Record<RoleName, Record<string, string[]>> = {
  viewer: { alerts: ["read"], reports: ["read"], detection: ["read"] },
  analyst: {
    alerts: ["read", "write"], detection: ["read", "run"], analysis: ["read", "run"],
    decision: ["read", "run"], actions: ["read", "approve", "deny", "execute", "rollback", "comment"],
    reports: ["read", "generate"],
  },
  admin: { "*": ["*"] },
};

export function usePermissions() {
  const { data: me } = useMe();
  const role = (me?.role ?? "viewer") as RoleName;
  const can = (resource: string, action: string): boolean => {
    const perms = PERMS[role] ?? {};
    if (perms["*"]?.includes("*")) return true;
    const acts = perms[resource] ?? perms["*"] ?? [];
    return acts.includes(action) || acts.includes("*");
  };
  return { role, can, isAdmin: role === "admin", isViewer: role === "viewer" };
}
