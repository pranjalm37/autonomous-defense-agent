# AADA — Testing Strategy

**188 tests, all offline** (no network, no live DB, no API keys). Run:

```bash
pytest tests/ -q --ignore=tests/test_auth.py   # 188 passed
```

(`test_auth.py` is the optional DB-integration tier — it needs a live Postgres.)

## The test pyramid

```
        ▲  attack simulations   (8)   end-to-end, realistic adversary behavior
       ╱ ╲ API tests           (14)   HTTP contract: routing, auth, RBAC, validation
      ╱   ╲ service/unit      (166)   pure logic, one component at a time
     ╱─────╲ (DB integration)         opt-in, needs Postgres
```

Most tests are fast unit/service tests; a thinner layer exercises the HTTP surface;
a few high-value end-to-end simulations prove the components work *together*.

## Test suites

| File | Layer | Covers |
|---|---|---|
| `test_detection.py` | unit | 6 detection rules, scoring, engine, FP guards |
| `test_rag.py` | unit | chunking, embeddings, similarity, retrieval |
| `test_ai_analyst.py` | unit | prompts, output schema, IOC/MITRE extraction |
| `test_decision.py` | unit | signal fusion, FP suppression, mode policy |
| `test_response.py` | unit | handlers, approval state machine, rollback, guardrails |
| `test_mcp_tools.py` | unit | 6 MCP tools + registry |
| `test_integrations.py` | unit | VT/AbuseIPDB/NVD clients, cache, rate limit, retry |
| `test_approval_workflow.py`, `test_audit_system.py`, `test_auth_rbac.py`, `test_reporting.py` | unit | audit, RBAC, reports |
| `test_schema_serialization.py` | unit | IP-address coercion on audit/alert/event fields, config list-env parsing |
| `test_simulator.py` | unit | attack scenario registry — parses/normalizes correctly, trips the expected detection rule, one case per scenario |
| **`test_api.py`** | **API** | **auth (401), RBAC (403), validation (422), DB-free endpoints end-to-end** |
| **`test_attack_simulations.py`** | **E2E** | **staged attacks through ingest → detect → analyze → decide** |

## Mock data & fixtures

- **`conftest.py`** — pins the suite offline (overrides `OPENAI_API_KEY`/`CHROMA_*`),
  and provides a `TestClient`, an `as_role(role)` factory (authenticates as
  viewer/analyst/admin via FastAPI dependency overrides against the *real*
  `require_roles` guards), and domain factories (`make_user`, `make_event`).
- **`attack_data.py`** — synthetic generators for the six threat classes, emitted
  in realistic on-the-wire formats (raw syslog, JSON events) so simulations run the
  *real* ingestion parsers + normalizer, not pre-baked objects.

## Security testing

This is a security product, so the tests assert *security properties*, not just
features:
- **Authorization is enforced server-side** — `test_api.py` proves a `viewer` gets
  **403** on detection/audit and an unauthenticated caller gets **401**, hitting the
  real guards (the UI hiding a button is never the only control).
- **Detection efficacy (true positives)** — the attack simulations stage SSH brute
  force, port scans, credential stuffing, malware/C2, and privilege escalation, and
  assert each is caught with the right MITRE technique and severity.
- **False positives** — a benign-traffic simulation asserts the engine stays
  **silent**; sub-threshold attacks (3 SSH failures) must *not* fire. FP control is
  a first-class test, because alert fatigue is a real failure mode.
- **Input safety** — parsers tolerate malformed records without crashing; the
  decision engine never auto-executes on weak/contradictory evidence.
- **Guardrails & least privilege** — `test_response.py` proves the engine refuses to
  block internal IPs or disable protected accounts; new users default to `viewer`.

## AI testing

LLM/ML components are non-deterministic, which breaks naive assertions. We handle
this with the same provider abstraction the app uses:
- **Deterministic offline providers** — tests run the `HeuristicLLMProvider` and
  `HashingEmbeddingProvider`, so the analyst and RAG pipeline are *reproducible*.
  This validates everything around the model — prompt assembly, the structured
  output **schema** (the contract the model must satisfy), grounding, IOC/MITRE
  extraction, and persistence — without flaky API calls.
- **Property-based assertions over the model** — instead of asserting exact prose,
  we assert invariants: risk ∈ [0,100], confidence ∈ [0,1], severity bands are
  monotonic, MITRE techniques carry tactics, recommended actions are approval-gated.
- **Retrieval quality** — RAG tests assert *ranking* properties ("shared vocabulary
  scores higher than unrelated"; the right source ranks first) rather than exact
  similarity floats.
- **Calibration & fusion** — decision tests assert that corroboration raises
  confidence and disagreement lowers it, and that the false-positive verdict is
  never produced for clearly high-risk inputs.
- **Prompt-injection hygiene** — evidence is fenced and labeled "data, not
  instructions" in the prompt; the system prompt test asserts the grounding +
  approval rules are present.

In production, swapping the real OpenAI/Chroma providers back in is a config change;
these tests pin the deterministic substitutes so CI is fast and reliable.
