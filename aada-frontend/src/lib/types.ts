/* API types — mirror the FastAPI backend schemas. */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus =
  | "new" | "analyzing" | "confirmed" | "false_positive" | "escalated" | "resolved";
export type ActionStatus =
  | "pending" | "approved" | "denied" | "executing" | "completed" | "failed" | "rolled_back";
export type DecisionMode = "monitor" | "assisted" | "autonomous";
export type Disposition =
  | "auto_execute" | "require_approval" | "escalate" | "monitor_only" | "suppress";

export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  source_ip: string | null;
  dest_ip: string | null;
  hostname: string | null;
  affected_user: string | null;
  threat_type: string | null;
  ai_confidence: number | null;
  incident_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface AlertList {
  total: number;
  items: Alert[];
}

export interface SecurityEvent {
  id: string;
  source: string;
  event_type: string;
  severity: Severity;
  source_ip: string | null;
  dest_ip: string | null;
  hostname: string | null;
  username: string | null;
  processed: boolean;
  ingested_at: string;
  alert_id: string | null;
  created_at: string;
}

export interface MitreTechnique { technique_id: string; name: string; tactic: string; }
export interface RecommendedAction {
  title: string; action_type: string; target: string;
  priority: string; rationale: string; reversible: boolean; requires_approval: boolean;
}
export interface AIAnalysis {
  is_true_positive: boolean;
  confidence: number;
  executive_summary: string;
  technical_analysis: string;
  attack_narrative: string;
  mitre_techniques: MitreTechnique[];
  mitre_tactics: string[];
  risk_score: number;
  recommended_severity: Severity;
  iocs: string[];
  recommended_actions: RecommendedAction[];
  references: string[];
  model: string | null;
}

export interface ActionDecisionItem {
  title: string; action_type: string; target: string;
  disposition: Disposition; reason: string;
}
export interface Decision {
  risk_score: number;
  confidence_score: number;
  verdict: "malicious" | "suspicious" | "benign" | "false_positive";
  mode: DecisionMode;
  is_false_positive: boolean;
  requires_human: boolean;
  top_disposition: Disposition;
  action_decisions: ActionDecisionItem[];
  rationale: string;
  signal_breakdown: Record<string, unknown>;
}

export interface Action {
  id: string;
  action_type: string;
  status: ActionStatus;
  target_type: string;
  target_value: string;
  ai_justification: string | null;
  risk_score: number | null;
  reversible: boolean;
  alert_id: string | null;
  created_at: string;
}
export interface ApprovalRecord {
  id: string; decision: string; notes: string | null;
  reviewer_id: string; reviewed_at: string;
}
export interface Comment {
  id: string; body: string; author_email: string | null;
  user_id: string | null; created_at: string;
}
export interface ActionDetail extends Action {
  approvals: ApprovalRecord[];
  comments: Comment[];
}
export interface ExecutionResult {
  ok: boolean; summary: string; status: ActionStatus;
  output: Record<string, unknown>; error: string | null;
}

export interface ReportListItem {
  id: string; report_type: string; title: string; summary: string | null;
  incident_id: string | null; alert_id: string | null; created_at: string;
}
export interface IncidentReport {
  report_id: string; title: string; severity: string; status: string; generated_at: string;
  executive_summary: string;
  timeline: { timestamp: string | null; category: string; title: string; detail: string | null }[];
  iocs: { ips: string[]; domains: string[]; hashes: string[]; urls: string[]; accounts: string[] };
  mitre: { technique_id: string; name: string; tactic: string | null }[];
  root_cause: string;
  recommendations: { title: string; detail: string | null; priority: string }[];
  metrics: Record<string, number>;
}

export interface AuditLog {
  id: string; action: string; resource_type: string; resource_id: string | null;
  user_id: string | null; user_email: string | null;
  old_value: Record<string, unknown> | null; new_value: Record<string, unknown> | null;
  ip_address: string | null; created_at: string;
}

export interface RuleInfo {
  rule_id: string; name: string; threat_type: string; thresholds: Record<string, number>;
}

export interface Token { access_token: string; refresh_token: string; token_type: string; }

export type RoleName = "viewer" | "analyst" | "admin";
export interface CurrentUser {
  id: string;
  email: string;
  username: string;
  full_name: string;
  role: RoleName | null;
  role_id: string | null;
  is_active: boolean;
  is_mfa_enabled: boolean;
  created_at: string;
}
