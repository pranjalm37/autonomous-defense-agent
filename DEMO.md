# Running & Demonstrating AADA

How to start the project, use it, and run a live **attack → detect → defend** demo.

---

## 1. Run the project

Everything is containerized. From the repo root:

```bash
cp .env.example .env          # first time only — set SECRET_KEY + DEFAULT_ADMIN_PASSWORD
docker compose up -d --build  # starts db, chroma, backend, frontend
docker compose ps             # all should be "healthy"
```

| Service | URL | Notes |
|---|---|---|
| **Dashboard (SPA)** | http://localhost:8080 | the UI you demo from |
| **API (Swagger)** | http://localhost:8000/docs | interactive API explorer |
| **Health** | http://localhost:8000/api/v1/health | `{"status":"ok"}` |

Default login (from `.env`): **`admin@aada.io` / `AadaAdmin!2026`**.

> Runs fully offline — no OpenAI/ChromaDB keys needed. Deterministic offline
> providers stand in for the LLM, embeddings, and threat-intel feeds, so the
> whole pipeline works for a demo. Add real API keys in `.env` to switch to live
> providers (no code change).

Stop with `docker compose down` (add `-v` to also wipe the database).

---

## 2. Use it — the autonomous-defense loop

AADA runs one pipeline end to end:

```
ingest → detect → analyze (AI+RAG) → decide → approve → respond → rollback → audit
```

You can drive it three ways:

- **The demo script** (§3) — one command, narrates every stage in the terminal.
- **The UI** (§4) — click through Alerts → Investigations → Approvals.
- **Swagger** (http://localhost:8000/docs) — call any of the 42 endpoints by hand.

---

## 3. Live attack → defense demo (one command)

```bash
./demo_attack.sh
```

This stages a **real SSH brute-force attack** and walks the whole loop. It:

1. Logs in, gets a JWT.
2. Generates a fresh SSH log — **8 failed logins + 1 success** from `185.220.101.34`
   within ~30s — and ingests it (`POST /events/upload`).
3. Runs the **detection engine** → raises a **critical `brute_force` alert**.
4. Runs the **AI SOC analyst** → true-positive, confidence 0.97, risk 100, MITRE
   mapping, recommends **block the source IP**.
5. Runs the **decision engine** (assisted mode) → verdict `malicious`, files a
   `block_ip` action into the approval queue.
6. Shows the **approval queue** (human-in-the-loop).
7. **Approves + executes** → `"Blocked 185.220.101.34"`.
8. **Rolls it back** → `"Unblocked 185.220.101.34"` (proves reversibility).
9. Prints the **audit trail** — every step attributed to `admin@aada.io`.

### Show the safety guardrail (great talking point)
Re-run pointed at an **internal** IP — the engine refuses to block it:

```bash
ATTACKER_IP=10.0.0.9 ./demo_attack.sh
```

> Step 7 returns *"blocked by safety guardrail: refusing to block internal/private
> address 10.0.0.9"*. The agent will not firewall your own infrastructure even when
> told to. (Same idea protects admin/root accounts from the disable-account action.)

---

## 4. Demo from the UI (for a live audience)

1. Open http://localhost:8080 and log in as the admin above.
2. In a terminal, fire the attack ingest+detect (or just run `./demo_attack.sh`
   and narrate the browser alongside it).
3. **Alerts** page → the new critical SSH brute-force alert appears.
4. Open it in **Investigations** → read the AI analyst's executive summary,
   technical analysis, MITRE techniques, and recommended actions.
5. **Approvals** queue → the `block_ip` action is *Pending*. Approve it (note the
   role-gated button — a `viewer` can't), then watch it execute. Add a comment;
   it's recorded on the action thread.
6. **Reports** → generate an incident report (PDF/JSON) for the alert.
7. Everything you did is in the **Audit log**.

---

## 5. Other attacks you can stage

The detection engine ships 6 rules. Quick ways to trip the others:

| Attack | How to stage |
|---|---|
| **SSH brute force** | `./demo_attack.sh` (above) |
| Port scan / cred stuffing / impossible travel / priv-esc / malware-C2 | bundled samples in `aada-backend/examples/` — upload via `POST /events/upload` (pick the matching `format`), then `POST /detection/run` |
| All of them at once | the offline attack-simulation suite: `cd aada-backend && pytest tests/test_attack_simulations.py -v` runs each staged attack through the real pipeline |

To craft your own, ingest events via `POST /events/json` (JSON) or
`POST /events/upload` (csv/ssh/auth/web), then `POST /detection/run`.

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `Login failed` in the script | stack not up — `docker compose ps`; check `DEFAULT_ADMIN_PASSWORD` in `.env` matches `ADMIN_PASS` |
| Detection shows `events_analyzed: 0` | events fell outside the lookback — the script stamps them at "now"; re-run it |
| Block returns the guardrail message | expected when `ATTACKER_IP` is internal/private (10.x, 192.168.x, 172.16.x) or a doc range (203.0.113.x) — use a public IP like `185.220.101.34` |
| Frontend shows "unhealthy" but loads | cosmetic healthcheck flap; the SPA still serves on :8080 |
```
