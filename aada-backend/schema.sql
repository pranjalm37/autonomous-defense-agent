-- ============================================================
-- AADA — AI Autonomous Defense Agent
-- PostgreSQL 16 Schema
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- trigram text search on titles
CREATE EXTENSION IF NOT EXISTS "btree_gin";  -- GIN on scalar columns

-- ============================================================
-- ENUMS
-- ============================================================

CREATE TYPE approval_decision  AS ENUM ('approved', 'denied', 'escalated');
CREATE TYPE action_status      AS ENUM ('pending', 'approved', 'denied', 'executing', 'completed', 'failed', 'rolled_back');
CREATE TYPE action_type        AS ENUM ('block_ip', 'unblock_ip', 'isolate_host', 'unisolate_host', 'kill_process', 'disable_user', 'enable_user', 'quarantine_file', 'delete_file', 'revoke_session', 'patch_vulnerability', 'reset_password', 'custom');
CREATE TYPE alert_status       AS ENUM ('new', 'analyzing', 'confirmed', 'false_positive', 'escalated', 'resolved');
CREATE TYPE event_severity     AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE event_source       AS ENUM ('siem', 'edr', 'firewall', 'ids', 'cloud', 'endpoint', 'manual');
CREATE TYPE incident_severity  AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE incident_status    AS ENUM ('open', 'investigating', 'contained', 'eradicated', 'recovered', 'closed');
CREATE TYPE report_type        AS ENUM ('incident_report', 'executive_summary', 'threat_analysis', 'compliance', 'forensic');
CREATE TYPE severity           AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE tool_status        AS ENUM ('success', 'failure', 'timeout', 'skipped');

-- ============================================================
-- TABLE: roles
-- Purpose: Fine-grained permission sets. One row per role.
--          Permissions stored as JSONB so they can be updated
--          at runtime without a schema migration.
-- ============================================================
CREATE TABLE roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(50) NOT NULL UNIQUE,    -- machine key: analyst_l1
    label       VARCHAR(100) NOT NULL,           -- display: "L1 Analyst"
    description TEXT,
    permissions JSONB       NOT NULL DEFAULT '{}',
    is_system   BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_roles_name ON roles (name);

-- ============================================================
-- TABLE: users
-- Purpose: Every human who authenticates to the platform.
--          Stores hashed password, MFA secret, session tracking,
--          and account lockout state.
-- ============================================================
CREATE TABLE users (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email               VARCHAR(255) NOT NULL UNIQUE,
    username            VARCHAR(100) NOT NULL UNIQUE,
    full_name           VARCHAR(255) NOT NULL,
    hashed_password     VARCHAR(255) NOT NULL,
    is_active           BOOLEAN     NOT NULL DEFAULT TRUE,
    is_mfa_enabled      BOOLEAN     NOT NULL DEFAULT FALSE,
    mfa_secret          VARCHAR(255),
    last_login_at       TIMESTAMPTZ,
    last_login_ip       INET,
    failed_login_count  INTEGER     NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    role_id             UUID        REFERENCES roles(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email    ON users (email);
CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_role_id  ON users (role_id);

-- ============================================================
-- TABLE: incidents
-- Purpose: Groups correlated alerts into one attack campaign.
--          Created by the AI agent when multiple alerts share
--          MITRE tactics or network overlap. Lifecycle follows
--          NIST IR: open → investigating → contained → closed.
-- Note: declared before alerts because alerts FK → incidents.
-- ============================================================
CREATE TABLE incidents (
    id              UUID              PRIMARY KEY DEFAULT gen_random_uuid(),
    title           VARCHAR(500)      NOT NULL,
    description     TEXT,
    severity        incident_severity NOT NULL,
    status          incident_status   NOT NULL DEFAULT 'open',
    mitre_tactics   TEXT[],           -- e.g. ARRAY['TA0001','TA0002']
    mitre_techniques TEXT[],
    ai_summary      TEXT,
    attack_chain    JSONB,            -- ordered list of TTP events with timestamps
    affected_assets JSONB,            -- {hosts:[], users:[], ips:[]}
    root_cause      TEXT,
    recommendations TEXT,
    contained_at    TIMESTAMPTZ,
    eradicated_at   TIMESTAMPTZ,
    recovered_at    TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ,
    assigned_to_id  UUID              REFERENCES users(id) ON DELETE SET NULL,
    created_by_id   UUID              REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ       NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ       NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_severity      ON incidents (severity);
CREATE INDEX idx_incidents_status        ON incidents (status);
CREATE INDEX idx_incidents_assigned_to   ON incidents (assigned_to_id);
CREATE INDEX idx_incidents_created_at    ON incidents (created_at DESC);
-- Full-text search on title + ai_summary
CREATE INDEX idx_incidents_fts ON incidents
    USING GIN (to_tsvector('english', coalesce(title,'') || ' ' || coalesce(ai_summary,'')));

-- ============================================================
-- TABLE: alerts
-- Purpose: Single AI-analyzed threat detection.  One or more
--          raw events trigger one alert.  Carries the full AI
--          reasoning chain, MITRE mapping, IOC list, and
--          confidence score.  May be promoted into an incident.
-- ============================================================
CREATE TABLE alerts (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        severity     NOT NULL,
    status          alert_status NOT NULL DEFAULT 'new',
    source_ip       INET,
    dest_ip         INET,
    hostname        VARCHAR(255),
    affected_user   VARCHAR(255),
    threat_type     VARCHAR(100),
    mitre_tactics   TEXT[],
    mitre_techniques TEXT[],
    ai_confidence   FLOAT        CHECK (ai_confidence BETWEEN 0 AND 1),
    ai_reasoning    TEXT,
    ai_analysis     JSONB,       -- full structured LLM output
    iocs            JSONB,       -- {ips:[], hashes:[], domains:[], urls:[]}
    affected_assets JSONB,
    resolved_at     TIMESTAMPTZ,
    incident_id     UUID         REFERENCES incidents(id) ON DELETE SET NULL,
    assigned_to_id  UUID         REFERENCES users(id)    ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_severity     ON alerts (severity);
CREATE INDEX idx_alerts_status       ON alerts (status);
CREATE INDEX idx_alerts_incident_id  ON alerts (incident_id);
CREATE INDEX idx_alerts_assigned_to  ON alerts (assigned_to_id);
CREATE INDEX idx_alerts_hostname     ON alerts (hostname);
CREATE INDEX idx_alerts_source_ip    ON alerts USING GIST (source_ip inet_ops);
CREATE INDEX idx_alerts_created_at   ON alerts (created_at DESC);
-- Partial index: only unresolved alerts (dashboards never query resolved)
CREATE INDEX idx_alerts_open ON alerts (severity, created_at DESC)
    WHERE status NOT IN ('resolved', 'false_positive');

-- ============================================================
-- TABLE: events
-- Purpose: Raw telemetry ingested from security tools.
--          Immutable after insert — never updated, only processed.
--          alert_id is set once the AI agent links the event to
--          an alert.  INET columns allow fast subnet queries.
-- ============================================================
CREATE TABLE events (
    id              UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    source          event_source   NOT NULL,
    source_event_id VARCHAR(255),               -- ID in the originating SIEM/EDR
    event_type      VARCHAR(100)   NOT NULL,
    severity        event_severity NOT NULL DEFAULT 'info',
    raw_payload     JSONB          NOT NULL,    -- original vendor blob
    normalized_payload JSONB,                  -- vendor-agnostic after ETL
    source_ip       INET,
    dest_ip         INET,
    source_port     INTEGER        CHECK (source_port BETWEEN 0 AND 65535),
    dest_port       INTEGER        CHECK (dest_port   BETWEEN 0 AND 65535),
    hostname        VARCHAR(255),
    username        VARCHAR(255),
    user_agent      TEXT,
    processed       BOOLEAN        NOT NULL DEFAULT FALSE,
    processed_at    TIMESTAMPTZ,
    ingested_at     TIMESTAMPTZ    NOT NULL,
    alert_id        UUID           REFERENCES alerts(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW()   -- SecurityEvent uses TimestampMixin
);

CREATE INDEX idx_events_source        ON events (source);
CREATE INDEX idx_events_event_type    ON events (event_type);
CREATE INDEX idx_events_severity      ON events (severity);
CREATE INDEX idx_events_processed     ON events (processed) WHERE processed = FALSE;
CREATE INDEX idx_events_alert_id      ON events (alert_id);
CREATE INDEX idx_events_hostname      ON events (hostname);
CREATE INDEX idx_events_ingested_at   ON events (ingested_at DESC);
CREATE INDEX idx_events_source_ip     ON events USING GIST (source_ip inet_ops);
CREATE UNIQUE INDEX idx_events_source_dedup
    ON events (source, source_event_id) WHERE source_event_id IS NOT NULL;

-- ============================================================
-- TABLE: actions
-- Purpose: Remediation steps proposed by the AI agent.
--          All actions start PENDING and require an approval
--          record before transitioning to APPROVED/EXECUTING.
--          risk_score (0–1) drives auto-approval thresholds.
-- ============================================================
CREATE TABLE actions (
    id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    action_type         action_type   NOT NULL,
    status              action_status NOT NULL DEFAULT 'pending',
    target_type         VARCHAR(50)   NOT NULL,   -- ip / host / process / user / file
    target_value        TEXT          NOT NULL,
    parameters          JSONB,
    ai_justification    TEXT,
    risk_score          FLOAT         CHECK (risk_score BETWEEN 0 AND 1),
    reversible          BOOLEAN       NOT NULL DEFAULT TRUE,
    rollback_procedure  TEXT,
    executed_at         TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    error_message       TEXT,
    alert_id            UUID          REFERENCES alerts(id)    ON DELETE SET NULL,
    incident_id         UUID          REFERENCES incidents(id) ON DELETE SET NULL,
    executed_by_id      UUID          REFERENCES users(id)     ON DELETE SET NULL,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_action_linked CHECK (alert_id IS NOT NULL OR incident_id IS NOT NULL)
);

CREATE INDEX idx_actions_status      ON actions (status);
CREATE INDEX idx_actions_action_type ON actions (action_type);
CREATE INDEX idx_actions_alert_id    ON actions (alert_id);
CREATE INDEX idx_actions_incident_id ON actions (incident_id);
CREATE INDEX idx_actions_created_at  ON actions (created_at DESC);
-- Fast lookup of pending actions for the approval queue UI
CREATE INDEX idx_actions_pending ON actions (created_at DESC) WHERE status = 'pending';

-- ============================================================
-- TABLE: approvals
-- Purpose: Human-in-the-loop decision record.
--          One action can accumulate multiple approval rows
--          (deny → escalate → approve by senior analyst).
--          The latest row with decision='approved' enables execution.
-- ============================================================
CREATE TABLE approvals (
    id               UUID              PRIMARY KEY DEFAULT gen_random_uuid(),
    decision         approval_decision NOT NULL,
    notes            TEXT,
    reviewed_at      TIMESTAMPTZ       NOT NULL,
    action_id        UUID              NOT NULL REFERENCES actions(id)  ON DELETE CASCADE,
    reviewer_id      UUID              NOT NULL REFERENCES users(id)    ON DELETE RESTRICT,
    escalated_to_id  UUID              REFERENCES users(id)             ON DELETE SET NULL
);

CREATE INDEX idx_approvals_action_id   ON approvals (action_id);
CREATE INDEX idx_approvals_reviewer_id ON approvals (reviewer_id);
CREATE INDEX idx_approvals_decision    ON approvals (decision);

-- ============================================================
-- TABLE: action_comments
-- Purpose: Collaborative review discussion on a proposed action,
--          separate from the approve/deny decision note. Preserves
--          the back-and-forth (questions, context) for the audit trail.
-- ============================================================
CREATE TABLE action_comments (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    body         TEXT        NOT NULL,
    author_email VARCHAR(255),                 -- denormalized; survives user deletion
    action_id    UUID        NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    user_id      UUID        REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_action_comments_action_id ON action_comments (action_id);
CREATE INDEX idx_action_comments_user_id   ON action_comments (user_id);
CREATE INDEX idx_action_comments_created   ON action_comments (action_id, created_at);

-- ============================================================
-- TABLE: reports
-- Purpose: AI-authored narrative documents (markdown).
--          Generated automatically after incident close or on
--          demand.  Linked to either an incident or an alert.
--          metadata_ column holds tags, version, export format.
-- ============================================================
CREATE TABLE reports (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type       report_type NOT NULL,
    title             VARCHAR(500) NOT NULL,
    content           TEXT        NOT NULL,   -- markdown body
    summary           TEXT,
    metadata_         JSONB,                  -- {tags:[], version:, format:}
    incident_id       UUID        REFERENCES incidents(id) ON DELETE SET NULL,
    alert_id          UUID        REFERENCES alerts(id)    ON DELETE SET NULL,
    generated_by_id   UUID        REFERENCES users(id)     ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_report_linked CHECK (incident_id IS NOT NULL OR alert_id IS NOT NULL)
);

CREATE INDEX idx_reports_report_type  ON reports (report_type);
CREATE INDEX idx_reports_incident_id  ON reports (incident_id);
CREATE INDEX idx_reports_alert_id     ON reports (alert_id);
CREATE INDEX idx_reports_created_at   ON reports (created_at DESC);
CREATE INDEX idx_reports_fts ON reports
    USING GIN (to_tsvector('english', coalesce(title,'') || ' ' || coalesce(summary,'')));

-- ============================================================
-- TABLE: audit_logs
-- Purpose: Immutable compliance trail.  Written by middleware
--          on every mutating API call.  Never updated or deleted.
--          user_email is denormalized so records survive user deletion.
--          Partitioned by month recommended for high-volume deployments.
-- ============================================================
CREATE TABLE audit_logs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        REFERENCES users(id) ON DELETE SET NULL,
    user_email    VARCHAR(255),
    action        VARCHAR(100) NOT NULL,       -- auth.login, ai.decision, action.executed, tool.call
    category      VARCHAR(32)  NOT NULL DEFAULT 'system',  -- user | ai | remediation | tool | system
    resource_type VARCHAR(100) NOT NULL,       -- alert / action / user / incident
    resource_id   UUID,
    old_value     JSONB,
    new_value     JSONB,
    ip_address    INET,
    user_agent    TEXT,
    request_id    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id       ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_action        ON audit_logs (action);
CREATE INDEX idx_audit_logs_category      ON audit_logs (category);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs (resource_type);
CREATE INDEX idx_audit_logs_resource_id   ON audit_logs (resource_id);
CREATE INDEX idx_audit_logs_created_at    ON audit_logs (created_at DESC);
-- Free-text search across actor + action (trigram; pg_trgm extension enabled above)
CREATE INDEX idx_audit_logs_search ON audit_logs
    USING GIN ((coalesce(user_email,'') || ' ' || action || ' ' || resource_type) gin_trgm_ops);
-- Compliance query: all events for one resource ordered newest-first
CREATE INDEX idx_audit_logs_resource ON audit_logs (resource_type, resource_id, created_at DESC);

-- ============================================================
-- TABLE: tool_logs
-- Purpose: Granular record of every MCP tool call made during
--          action execution.  One action may spawn multiple tool
--          calls (e.g. block_ip → verify_block → notify_soc).
--          duration_ms powers latency dashboards and SLA checks.
-- ============================================================
CREATE TABLE tool_logs (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name    VARCHAR(100) NOT NULL,
    tool_version VARCHAR(50),
    input_params JSONB,
    output       JSONB,
    status       tool_status  NOT NULL,
    error_message TEXT,
    duration_ms  INTEGER,
    retry_count  INTEGER      NOT NULL DEFAULT 0,
    executed_at  TIMESTAMPTZ  NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    action_id    UUID         REFERENCES actions(id) ON DELETE SET NULL
);

CREATE INDEX idx_tool_logs_tool_name  ON tool_logs (tool_name);
CREATE INDEX idx_tool_logs_status     ON tool_logs (status);
CREATE INDEX idx_tool_logs_action_id  ON tool_logs (action_id);
CREATE INDEX idx_tool_logs_executed_at ON tool_logs (executed_at DESC);

-- ============================================================
-- SEED: default roles (also seeded programmatically by app/db/seed.py)
-- ============================================================
INSERT INTO roles (name, label, description, permissions) VALUES
('viewer',  'Viewer',        'Read-only access to dashboards, alerts, and reports.',
 '{"alerts":["read"],"events":["read"],"detection":["read"],"reports":["read"],"knowledge":["read","query"],"audit":["read"]}'),
('analyst', 'Analyst',       'Investigate, run the AI agents, and action remediations.',
 '{"alerts":["read","write"],"events":["read","write"],"detection":["read","run"],"analysis":["read","run"],"decision":["read","run"],"actions":["read","approve","deny","execute","rollback","comment"],"reports":["read","generate"],"knowledge":["read","query"],"audit":["read"]}'),
('admin',   'Administrator', 'Full system access including user and role management.',
 '{"*":["*"]}')
ON CONFLICT (name) DO NOTHING;
