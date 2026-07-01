/*
 * Global client state (Zustand).
 *
 * Server data lives in React Query; this store holds only *client* state that
 * must persist and be read outside React (e.g. the auth token, read by the API
 * client). Persisted to localStorage so a refresh keeps you signed in and keeps
 * the selected defense mode.
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { DecisionMode } from "@/lib/types";

interface AppState {
  token: string | null;
  setToken: (t: string | null) => void;

  defenseMode: DecisionMode;
  setDefenseMode: (m: DecisionMode) => void;

  sidebarCollapsed: boolean;
  toggleSidebar: () => void;

  isAuthenticated: () => boolean;
}

export const useAppStore = create<AppState>()(
  persist(
    (set, get) => ({
      token: null,
      setToken: (token) => set({ token }),

      defenseMode: "assisted",
      setDefenseMode: (defenseMode) => set({ defenseMode }),

      sidebarCollapsed: false,
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

      isAuthenticated: () => !!get().token,
    }),
    {
      name: "aada-app",
      partialize: (s) => ({ token: s.token, defenseMode: s.defenseMode }),
    },
  ),
);
