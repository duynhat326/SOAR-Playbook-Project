export type Severity = "low" | "medium" | "high" | "critical";
export type RiskLevel = Severity;
export type ScenarioKey =
  | "malicious_hash"
  | "c2_communication"
  | "critical_asset"
  | "dangerous_process"
  | "mixed"
  | "benign"
  | "random";
export type IntakeMode = "scenario" | "sample" | "json";
export type ApiMode = "api" | "mock";

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
}

export interface HashEnrichment {
  hash_value?: string;
  reputation: "clean" | "suspicious" | "malicious" | "unknown";
  malicious_vendors: number;
  total_vendors: number;
  threat_name?: string | null;
  source: string;
}

export interface IPEnrichment {
  ip_address: string;
  reputation: "clean" | "unknown" | "malicious";
  confidence_score: number;
  is_c2: boolean;
  country?: string | null;
  isp?: string | null;
  source: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  matched_pattern: string;
  confidence: number;
}

export interface EnrichedAlert {
  original_alert: MalwareAlert;
  hash_enrichment?: HashEnrichment;
  ip_enrichment?: IPEnrichment;
  asset_criticality: "normal" | "high" | "critical";
  mitre_mappings: MitreMapping[];
  risk_score: number;
  risk_level: RiskLevel;
  enriched_at: string;
}

export interface ActionResult {
  action: string;
  status: "success" | "failed" | "queued" | "skipped";
  executed_at: string;
  details: string;
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
}

export interface ExecutionTrace {
  configured_mode: string;
  effective_mode: string;
  queue_name?: string | null;
  fallback_reason?: string | null;
  queued_actions: QueuedActionRequest[];
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
  execution_trace?: ExecutionTrace;
}

export interface IncidentSummary {
  id: number;
  alert_id: string;
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

export type ProcessAlertInput =
  | { mode: "scenario"; scenario: ScenarioKey }
  | { mode: "sample"; sampleId: string }
  | { mode: "json"; rawJson: string };
