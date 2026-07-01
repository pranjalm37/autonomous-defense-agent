# API Reference

Base URL: `/api/v1` · Auth: `Authorization: Bearer <access_token>` ·
Interactive docs: `http://localhost:8000/docs`

**42 endpoints** across 13 modules. Roles: **V**iewer (read-only), **A**nalyst
(operate), **Ad**min (everything). Admin satisfies any role check.

## Auth
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/auth/login` | — | OAuth2 password flow → access + refresh JWT |
| POST | `/auth/register` | — | Create account (defaults to `viewer`) |
| POST | `/auth/refresh` | — | Exchange a refresh token for a new pair |
| GET | `/auth/me` | any | Current user + role |

## Events (ingestion)
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/events/json` | A | Ingest JSON events (object / array / NDJSON) |
| POST | `/events/upload` | A | Ingest a CSV / SSH / auth / web log file (`format` field) |
| GET | `/events` | any | List events (filter source/severity/processed) |
| GET | `/events/{id}` | any | Event detail |

## Detection
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/detection/run` | A | Run the 6-rule engine over recent events → alerts |
| GET | `/detection/rules` | any | List rules + tunable thresholds |

## Alerts
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/alerts` | any | List/filter (severity, status, pagination) |
| GET | `/alerts/{id}` | any | Alert detail |
| POST | `/alerts` | A | Create alert |
| PATCH | `/alerts/{id}` | any | Update status / assignment |
| DELETE | `/alerts/{id}` | Ad | Delete alert |

## AI Analyst
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/analyst/alerts/{id}/analyze` | A | LLM analysis of a stored alert (persisted) |
| POST | `/analyst/analyze` | any | Ad-hoc analysis of a supplied alert payload |

## Decision Engine
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/decision/alerts/{id}/decide` | A | Fuse signals → risk/confidence/disposition (`?mode=`, `?create_actions=`) |
| POST | `/decision/evaluate` | any | Ad-hoc decision over supplied signals |

## Response / Approval workflow
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/response/actions` | any | Action queue (filter by status) |
| GET | `/response/actions/{id}` | any | Detail: approvals + comment thread |
| POST | `/response/actions/{id}/approve` | A | Approve → APPROVED (audited) |
| POST | `/response/actions/{id}/deny` | A | Reject → DENIED (audited) |
| POST | `/response/actions/{id}/comments` | A | Add a review comment |
| GET | `/response/actions/{id}/comments` | any | List comments |
| POST | `/response/actions/{id}/execute` | A | Run an APPROVED action (records ToolLog) |
| POST | `/response/actions/{id}/rollback` | A | Undo a COMPLETED reversible action |

## Knowledge (RAG)
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/knowledge/query` | any | Semantic search over the knowledge base |
| GET | `/knowledge/stats` | any | Vector count + active providers |
| POST | `/knowledge/ingest` | A | (Re)load and embed all knowledge sources |

## Reports
| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/reports/incidents/{id}/generate` | A | Generate an incident report |
| POST | `/reports/alerts/{id}/generate` | A | Generate a report from one alert |
| GET | `/reports` | any | List reports |
| GET | `/reports/{id}` | any | Structured report (JSON body) |
| GET | `/reports/{id}/export.json` | any | Download JSON |
| GET | `/reports/{id}/export.pdf` | any | Download PDF |

## Audit
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/audit/logs` | A | Search (free-text `q`, category, action, resource, date range, pagination) |
| GET | `/audit/logs/{id}` | A | Single entry |
| GET | `/audit/tools` | A | Tool-call trail (`tool_logs`) |
| GET | `/audit/timeline/{rtype}/{rid}` | A | Merged audit + tool timeline for a resource |
| GET | `/audit/stats` | A | Facet counts over a window |

## Health
| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/health` | — | Liveness + DB connectivity (k8s/Docker probe) |

## Example: full triage flow

```bash
# 1. authenticate
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login \
  -d "username=admin@aada.io&password=…" | jq -r .access_token)
A="Authorization: Bearer $TOKEN"

# 2. ingest → detect
curl -s -X POST localhost:8000/api/v1/events/json -H "$A" -H 'Content-Type: application/json' -d @attack.json
curl -s -X POST localhost:8000/api/v1/detection/run -H "$A" -H 'Content-Type: application/json' -d '{"lookback_minutes":60}'

# 3. analyze → decide (assisted: queues for approval)
ALERT=$(curl -s "localhost:8000/api/v1/alerts?limit=1" -H "$A" | jq -r .items[0].id)
curl -s -X POST "localhost:8000/api/v1/analyst/alerts/$ALERT/analyze" -H "$A"
curl -s -X POST "localhost:8000/api/v1/decision/alerts/$ALERT/decide?mode=assisted&create_actions=true" -H "$A"

# 4. approve → execute → report
ACT=$(curl -s "localhost:8000/api/v1/response/actions?status=pending" -H "$A" | jq -r .[0].id)
curl -s -X POST "localhost:8000/api/v1/response/actions/$ACT/approve" -H "$A" -d '{}'
curl -s -X POST "localhost:8000/api/v1/response/actions/$ACT/execute" -H "$A"
curl -s -X POST "localhost:8000/api/v1/reports/alerts/$ALERT/generate" -H "$A"
```

## Errors

Domain errors map to HTTP status via a typed hierarchy: `401` unauthenticated,
`403` RBAC denied, `404` not found, `409` conflict, `422` validation. Bodies follow
`{"error": {"code": "...", "message": "..."}}`.
