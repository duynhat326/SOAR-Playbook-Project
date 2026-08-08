export type Severity = "low" | "medium" | "high" | "critical";
export type RiskLevel = Severity;
export type ActionExecutionStatus = "queued" | "waiting_approval" | "running" | "succeeded" | "failed" | "skipped";
export type ActionApprovalState = "not_required" | "pending" | "approved" | "rejected";
export type HashReputation = "clean" | "suspicious" | "malicious" | "unknown";
export type IPReputation = "clean" | "unknown" | "malicious";
export type AssetCriticality = "low" | "normal" | "critical";
export type PolicyStatus = "draft" | "active" | "disabled" | "deprecated";
export type IncidentCaseStatus = "new" | "triaged" | "in_progress" | "monitoring" | "resolved" | "closed";
export type CorrelationOutcome = "new_incident" | "attached_to_existing" | "reopened_incident";
export type ScenarioKey =
  | "malicious_hash"
  | "c2_communication"
  | "critical_asset"
  | "dangerous_process"
  | "mixed"
  | "benign"
  | "random";
export type IntakeMode = "scenario" | "sample" | "json";
export type ApiMode = "api" | "offline";

export interface MalwareAlert {
  alert_id: string;
  hostname: string;
  username: string;
  process_name: string;
  file_path: string;
  file_hash: string;
  parent_process: string;
  command_line: string;
  destination_ip: string;
  severity: Severity;
  detection_name: string;
  received_at?: string;
}

export interface HashEnrichment {
  hash_value?: string;
  reputation: HashReputation;
  malicious_vendors: number;
  suspicious_vendors: number;
  harmless_vendors: number;
  undetected_vendors: number;
  total_vendors: number;
  threat_name?: string | null;
  meaningful_name?: string | null;
  community_reputation?: number | null;
  tags: string[];
  analysis_stats: Record<string, number>;
  last_analysis_date?: string | null;
  permalink?: string | null;
  source: string;
}

export interface IPEnrichment {
  ip_address: string;
  reputation: IPReputation;
  confidence_score: number;
  is_c2: boolean;
  country?: string | null;
  isp?: string | null;
  asn?: number | null;
  network?: string | null;
  malicious_vendors: number;
  suspicious_vendors: number;
  harmless_vendors: number;
  undetected_vendors: number;
  tags: string[];
  analysis_stats: Record<string, number>;
  community_reputation?: number | null;
  last_analysis_date?: string | null;
  permalink?: string | null;
  source: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  matched_pattern: string;
  confidence: number;
}

export interface RiskBreakdownComponent {
  raw: number;
  contribution: number;
}

export interface RiskBreakdown {
  hash?: RiskBreakdownComponent;
  ip?: RiskBreakdownComponent;
  asset?: RiskBreakdownComponent;
  severity?: RiskBreakdownComponent;
  mitre?: RiskBreakdownComponent;
  total?: number;
  risk_level?: string;
  reasoning: string[];
}

export interface EnrichedAlert {
  original_alert: MalwareAlert;
  hash_enrichment?: HashEnrichment;
  ip_enrichment?: IPEnrichment;
  asset_criticality: AssetCriticality;
  asset_info: Record<string, unknown>;
  mitre_mappings: MitreMapping[];
  risk_score: number;
  risk_level: RiskLevel;
  risk_breakdown: RiskBreakdown;
  enriched_at: string;
}

export interface ActionResult {
  action: string;
  status: ActionExecutionStatus;
  executed_at: string;
  details: string;
  correlation_id?: string | null;
  attempt_count: number;
  updated_at: string;
  requires_approval: boolean;
  approval_state: ActionApprovalState;
  approval_reason?: string | null;
  approval_comment?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  approval_due_at?: string | null;
  approval_escalates_at?: string | null;
  escalation_targets: string[];
  approval_escalated_at?: string | null;
  rollback_requested_by?: string | null;
  rollback_requested_at?: string | null;
  operator?: string | null;
  policy_version?: number | null;
}

export interface CorrelationHook {
  field: string;
  value: string;
}

export interface QueuedActionRequest {
  action: string;
  queue_name: string;
  correlation_id: string;
  deduplication_key: string;
  correlation_hooks: CorrelationHook[];
  payload: Record<string, unknown>;
  requires_approval: boolean;
  approval_state: ActionApprovalState;
  approval_reason?: string | null;
  approval_comment?: string | null;
  approved_by?: string | null;
  approved_at?: string | null;
  approval_due_at?: string | null;
  approval_escalates_at?: string | null;
  escalation_targets: string[];
  approval_escalated_at?: string | null;
  rollback_requested_by?: string | null;
  rollback_requested_at?: string | null;
  requested_at?: string;
}

export interface ExecutionTrace {
  configured_mode: string;
  effective_mode: string;
  queue_name?: string | null;
  fallback_reason?: string | null;
  queued_actions: QueuedActionRequest[];
  policy_version?: number | null;
  policy_status?: PolicyStatus | null;
  canary_enabled?: boolean;
  canary_targeted?: boolean | null;
  canary_reason?: string | null;
  canary_percentage?: number | null;
  canary_bucket?: number | null;
}

export interface PolicyMetadataSnapshot {
  version: number;
  status: PolicyStatus;
  owner: string;
  change_reason: string;
  created_at: string;
}

export interface CorrelationEvidence {
  strategy: string;
  fields: string[];
  fingerprint: string;
  values: Record<string, string>;
  matched_alert_ids: string[];
}

export interface IncidentCorrelationTrace {
  enabled: boolean;
  window?: string | null;
  outcome: CorrelationOutcome;
  incident_key?: string | null;
  matched_incident_id?: number | null;
  matched_alert_ids: string[];
  related_alert_ids: string[];
  related_alert_count: number;
  evidence: CorrelationEvidence[];
  candidate_fingerprints: CorrelationEvidence[];
}

export interface ReportArtifacts {
  markdown_path?: string | null;
  html_path?: string | null;
  pdf_path?: string | null;
  markdown_content?: string | null;
}

export interface IncidentResponse {
  enriched_alert: EnrichedAlert;
  triggered_actions: string[];
  policy_reasoning: string[];
  action_results: ActionResult[];
  ticket_id?: string | null;
  completed_at: string;
  report_path?: string | null;
  policy_version?: number | null;
  policy_metadata?: PolicyMetadataSnapshot | null;
  correlation_trace?: IncidentCorrelationTrace;
  execution_trace?: ExecutionTrace;
}

export interface IncidentSummary {
  id: number;
  alert_id: string;
  incident_key: string;
  latest_alert_id: string;
  hostname: string;
  detection_name: string;
  risk_score: number;
  risk_level: RiskLevel;
  severity?: Severity;
  process_name?: string;
  destination_ip?: string;
  ticket_id?: string | null;
  status: string;
  completed_at: string;
  report_path?: string | null;
  case_status: IncidentCaseStatus;
  case_owner?: string | null;
  queued_action_count: number;
  pending_approval_count: number;
  running_action_count: number;
  failed_action_count: number;
  succeeded_action_count: number;
  active_action_count: number;
  note_count: number;
  related_alert_count: number;
}

export interface IncidentNote {
  note_id: string;
  author: string;
  body: string;
  created_at: string;
  updated_at: string;
}

export interface IncidentAuditEvent {
  event_id: string;
  category: string;
  actor: string;
  message: string;
  payload: Record<string, unknown>;
  previous_event_hash?: string | null;
  event_hash?: string | null;
  created_at: string;
}

export interface IncidentRecord extends IncidentSummary {
  triggered_actions: string[];
  policy_reasoning: string[];
  action_results: ActionResult[];
  created_at: string;
  updated_at: string;
  alert: MalwareAlert;
  response: IncidentResponse;
  report: ReportArtifacts;
  enriched_alert: EnrichedAlert;
  notes: IncidentNote[];
  audit_events: IncidentAuditEvent[];
  related_alert_ids: string[];
}

export interface ScenarioOption {
  value: ScenarioKey;
  label: string;
  description: string;
}

export interface SampleOption {
  value: string;
  label: string;
  scenario: ScenarioKey;
  description: string;
}

export interface DashboardBootstrap {
  scenario_options: ScenarioOption[];
  sample_options: SampleOption[];
  sample_alerts: Record<string, MalwareAlert>;
  default_sample_id?: string | null;
  default_scenario: ScenarioKey;
  default_json: string;
}

export interface SavedFilter {
  id: number;
  name: string;
  filters: Record<string, unknown>;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface DependencyReadiness {
  name: string;
  provider: string;
  status: string;
  detail: string;
  meta: Record<string, unknown>;
}

export interface ReadinessState {
  status: string;
  dependencies: DependencyReadiness[];
  queue_metrics: Record<string, unknown>;
  observability: Record<string, unknown>;
}

export type ProcessAlertInput =
  | { mode: "scenario"; scenario: ScenarioKey }
  | { mode: "sample"; sampleId: string }
  | { mode: "json"; rawJson: string };
