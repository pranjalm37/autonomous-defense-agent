#!/usr/bin/env bash
#
# demo_attack.sh — End-to-end AADA demo.
#
# Stages a live SSH brute-force attack, then walks the autonomous-defense loop:
#   ingest -> detect -> AI analyze -> decide -> approve -> execute (block IP)
#   -> rollback -> audit
#
# Requires: the stack running (docker compose up -d) and `jq`.
# Usage:    ./demo_attack.sh
#
# Tip: set ATTACKER_IP to an internal address (e.g. 10.0.0.9) to watch the
#      safety guardrail REFUSE the block instead of executing it.
#
set -euo pipefail

API="${API:-http://localhost:8000/api/v1}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@aada.io}"
ADMIN_PASS="${ADMIN_PASS:-AadaAdmin!2026}"
ATTACKER_IP="${ATTACKER_IP:-185.220.101.34}"   # globally routable -> block allowed

bold(){ printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }
note(){ printf "   \033[2m%s\033[0m\n" "$1"; }

# ── 0. Auth ────────────────────────────────────────────────────────────────
bold "0. Login as admin"
TOKEN=$(curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=$ADMIN_EMAIL" \
  --data-urlencode "password=$ADMIN_PASS" | jq -r .access_token)
[ "$TOKEN" != "null" ] && [ -n "$TOKEN" ] || { echo "Login failed"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")
note "got JWT access token"

# ── 1. Stage the attack (generate a fresh SSH brute-force log) ──────────────
bold "1. Stage attack: SSH brute force from $ATTACKER_IP"
LOG=$(mktemp "${TMPDIR:-/tmp}/aada_ssh.XXXXXX")
# 8 failed logins inside ~25s, then a SUCCESS from the same IP (= breach).
# Timestamps are in the recent PAST so they fall inside the detection lookback.
USERS=(root admin oracle postgres test deploy ubuntu git)
for i in 0 1 2 3 4 5 6 7; do
  OFF=$((35 - i * 3))   # -35s .. -14s
  TS=$(date -u -v-${OFF}S "+%b %e %H:%M:%S" 2>/dev/null || date -u -d "-${OFF} seconds" "+%b %e %H:%M:%S")
  printf '%s web01 sshd[%d]: Failed password for invalid user %s from %s port 5%d ssh2\n' \
    "$TS" "$((12000+i))" "${USERS[$i]}" "$ATTACKER_IP" "$((4300+i))" >> "$LOG"
done
TS=$(date -u -v-8S "+%b %e %H:%M:%S" 2>/dev/null || date -u -d "-8 seconds" "+%b %e %H:%M:%S")
printf '%s web01 sshd[12099]: Accepted password for root from %s port 54399 ssh2\n' \
  "$TS" "$ATTACKER_IP" >> "$LOG"
note "$(wc -l < "$LOG" | tr -d ' ') log lines (8 failures + 1 success)"

INGEST=$(curl -s -X POST "$API/events/upload" "${AUTH[@]}" \
  -F "format=ssh" -F "file=@$LOG")
note "ingested: $(echo "$INGEST" | jq -c '{received, stored, failed}')"

# ── 2. Detect ──────────────────────────────────────────────────────────────
bold "2. Run detection engine"
DET=$(curl -s -X POST "$API/detection/run" "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -d '{"lookback_minutes": 1440, "only_unprocessed": true}')
note "summary: $(echo "$DET" | jq -c '{events_analyzed, detections, alerts_created}')"

# ── 3. Inspect the alert this attack raised ─────────────────────────────────
bold "3. Alert raised"
ALERT=$(curl -s "$API/alerts?limit=10" "${AUTH[@]}" \
  | jq --arg ip "$ATTACKER_IP" '[.items[] | select(.source_ip==$ip)][0]')
ALERT_ID=$(echo "$ALERT" | jq -r '.id')
[ "$ALERT_ID" != "null" ] && [ -n "$ALERT_ID" ] || { echo "No alert for $ATTACKER_IP"; exit 1; }
echo "$ALERT" | jq '{id, title, severity, status, source_ip, threat_type}'

# ── 4. AI SOC analyst ───────────────────────────────────────────────────────
bold "4. AI analyst investigates (RAG-grounded)"
AN=$(curl -s -X POST "$API/analyst/alerts/$ALERT_ID/analyze" "${AUTH[@]}")
echo "$AN" | jq '{is_true_positive, confidence, recommended_severity, risk_score,
                  executive_summary,
                  recommended_actions: [.recommended_actions[]? | {action_type, target, priority}]}'

# ── 5. Decision engine → queue remediation ──────────────────────────────────
bold "5. Decision engine (assisted mode) files actions for approval"
DEC=$(curl -s -X POST "$API/decision/alerts/$ALERT_ID/decide?mode=assisted&create_actions=true" "${AUTH[@]}")
echo "$DEC" | jq '{verdict, risk_score, confidence_score, top_disposition, rationale}'

# ── 6. Approval queue ───────────────────────────────────────────────────────
bold "6. Approval queue (human-in-the-loop)"
ACTIONS=$(curl -s "$API/response/actions?status=pending" "${AUTH[@]}")
echo "$ACTIONS" | jq --arg ip "$ATTACKER_IP" \
  '[.[] | select(.target_value==$ip) | {id, action_type, status, target_value, reversible}]'
ACTION_ID=$(echo "$ACTIONS" | jq -r --arg ip "$ATTACKER_IP" \
  '[.[] | select(.action_type=="block_ip" and .target_value==$ip)][0].id')
[ "$ACTION_ID" != "null" ] && [ -n "$ACTION_ID" ] || { echo "No block_ip action queued"; exit 1; }

# ── 7. Approve + execute (the defense) ──────────────────────────────────────
bold "7. Approve + execute remediation -> block $ATTACKER_IP"
curl -s -X POST "$API/response/actions/$ACTION_ID/approve" "${AUTH[@]}" \
  -H "Content-Type: application/json" -d '{"note":"Confirmed brute force; blocking."}' \
  | jq '{id, status}'
EXEC=$(curl -s -X POST "$API/response/actions/$ACTION_ID/execute" "${AUTH[@]}")
echo "$EXEC" | jq '{ok, status, summary}'

# ── 8. Rollback (prove reversibility) ───────────────────────────────────────
if [ "$(echo "$EXEC" | jq -r .ok)" = "true" ]; then
  bold "8. Roll back the block (reversibility)"
  curl -s -X POST "$API/response/actions/$ACTION_ID/rollback" "${AUTH[@]}" \
    | jq '{ok, status, summary}'
fi

# ── 9. Audit trail ──────────────────────────────────────────────────────────
bold "9. Audit trail (who/what/when across the whole loop)"
curl -s "$API/audit/logs?limit=8" "${AUTH[@]}" \
  | jq '[.items[]? | {action, category, resource_type, actor: (.user_email // "system")}]'

bold "DONE"
note "Attack detected, analyzed, decided, approved, blocked, and rolled back — fully audited."
note "See it in the UI at http://localhost:8080  (Alerts / Investigations / Approvals)"
rm -f "$LOG"
