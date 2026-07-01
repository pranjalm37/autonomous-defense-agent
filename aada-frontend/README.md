# AADA Frontend

React + TypeScript + Tailwind + shadcn/ui dashboard for the AI Autonomous Defense Agent.

## Run
```bash
npm install
cp .env.example .env        # VITE_API_BASE defaults to /api/v1 (proxied to :8000)
npm run dev                 # http://localhost:5173
npm run build               # type-check + production build
```
The dev server proxies `/api` → `http://localhost:8000` (the FastAPI backend).

## Architecture
- **Routing:** `react-router-dom` — 5 pages under a shared `AppLayout` (sidebar + topbar).
- **Server state:** `@tanstack/react-query` (`src/hooks/queries.ts`) — caching, dedupe,
  mutations that invalidate affected queries. Components never call the API directly.
- **Client state:** `zustand` (`src/store/appStore.ts`) — auth token + defense mode,
  persisted to localStorage and readable outside React (the API client reads the token).
- **API:** one typed client (`src/lib/api.ts`) over `fetch`; types in `src/lib/types.ts`
  mirror the backend schemas.
- **UI:** shadcn-style primitives in `src/components/ui/*` (CVA variants + `cn`), themed
  via CSS variables in `src/index.css` (cyber-SOC dark palette).

## Pages
| Page | Route | Backend |
|---|---|---|
| Dashboard | `/` | alerts, actions, detection/run |
| Alerts | `/alerts` | alerts (filter/search) |
| Investigations | `/investigations?alert=` | analyst, decision, response (approve/deny) |
| Reports | `/reports` | reports (generate, PDF/JSON export) |
| Settings | `/settings` | detection/rules, audit/logs, defense mode |
