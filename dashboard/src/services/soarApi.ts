import type {
  ActionApprovalState,
  ActionResult,
  ActionExecutionStatus,
  ApiMode,
  DashboardBootstrap,
  DependencyReadiness,
  EnrichedAlert,
  ExecutionTrace,
  HashEnrichment,
  IncidentAuditEvent,
  IncidentCaseStatus,
  IncidentNote,
  IncidentRecord,
  IncidentSummary,
  IPEnrichment,
  MalwareAlert,
  ProcessAlertInput,
  QueuedActionRequest,
  ReadinessState,
  ReportArtifacts,
  RiskBreakdown,
  RiskLevel,
  SampleOption,
  ScenarioKey,
  ScenarioOption,
  SavedFilter,
} from "../types";

const EXPLICIT_API_BASE_URL = (import.meta.env.VITE_SOAR_API_BASE_URL ?? "").trim().replace(/\/$/, "");
const DEV_PROXY_BASE_URL = import.meta.env.DEV ? "/soar-api" : "";
const API_BASE_URL = (EXPLICIT_API_BASE_URL || DEV_PROXY_BASE_URL).replace(/\/$/, "");
const AUTH_STORAGE_KEY = "soar.dashboard.authToken";

const EMPTY_ALERT: MalwareAlert = {
  alert_id: "pending-alert",
  hostname: "pending-host",
  username: "pending-user",
  process_name: "pending-process",
  file_path: "C:\\path\\to\\sample.exe",
  file_hash: "44d88612fea8a8f36de82e1278abb02f",
  parent_process: "explorer.exe",
  command_line: "sample.exe --flag",
  destination_ip: "8.8.8.8",
  severity: "medium",
  detection_name: "Malware.Sample",
};

const fallbackDashboardBootstrap: DashboardBootstrap = {
  scenario_options: [],
  sample_options: [],
  sample_alerts: {},
  default_sample_id: null,
  default_scenario: "mixed",
  default_json: JSON.stringify(EMPTY_ALERT, null, 2),
};

let dashboardAuthToken = readStoredAuthToken();

function readStoredAuthToken(): string {
  if (typeof window === "undefined") {
    return "";
  }

  try {
    return (window.sessionStorage.getItem(AUTH_STORAGE_KEY) ?? "").trim();
  } catch {
    return "";
  }
}

function getStoredDashboardAuthToken(): string {
  const stored = readStoredAuthToken();
  if (stored !== dashboardAuthToken) {
    dashboardAuthToken = stored;
  }
  return dashboardAuthToken;
}

export function getDashboardAuthToken(): string {
  return getStoredDashboardAuthToken();
}

export function setDashboardAuthToken(token: string): string {
  dashboardAuthToken = token.trim();

  if (typeof window !== "undefined") {
    try {
      if (dashboardAuthToken.length > 0) {
        window.sessionStorage.setItem(AUTH_STORAGE_KEY, dashboardAuthToken);
      } else {
        window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
      }
    } catch {
    }
  }

  return dashboardAuthToken;
}

export function clearDashboardAuthToken(): void {
  setDashboardAuthToken("");
}

function canUseApi(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  if (EXPLICIT_API_BASE_URL.length > 0) {
    return true;
  }

  return window.location.protocol !== "file:";
}

function ensureApiAvailable(): void {
  if (!canUseApi()) {
    throw new Error("The dashboard must run behind the SOAR API. Start the backend and open the app through Vite or Vercel.");
  }
}

function normalizeRiskLevel(value: unknown): RiskLevel {
  const candidate = String(value ?? "low").toLowerCase();
  if (candidate === "critical" || candidate === "high" || candidate === "medium" || candidate === "low") {
    return candidate;
  }
  return "low";
}

function normalizeScenarioKey(value: unknown): ScenarioKey {
  const candidate = String(value ?? "mixed").toLowerCase();
  if (
    candidate === "malicious_hash" ||
    candidate === "c2_communication" ||
    candidate === "critical_asset" ||
    candidate === "dangerous_process" ||
    candidate === "mixed" ||
    candidate === "benign" ||
    candidate === "random"
  ) {
    return candidate;
  }
  return "mixed";
}

function normalizeAssetCriticality(value: unknown): EnrichedAlert["asset_criticality"] {
  const candidate = String(value ?? "normal").toLowerCase();
  if (candidate === "critical" || candidate === "normal" || candidate === "low") {
    return candidate;
  }
  return "normal";
}

function fallbackAlert(): MalwareAlert {
  return { ...EMPTY_ALERT };
}

function normalizeAlert(payload: any): MalwareAlert {
  return {
    alert_id: String(payload?.alert_id ?? EMPTY_ALERT.alert_id),
    hostname: String(payload?.hostname ?? EMPTY_ALERT.hostname),
    username: String(payload?.username ?? EMPTY_ALERT.username),
    process_name: String(payload?.process_name ?? EMPTY_ALERT.process_name),
    file_path: String(payload?.file_path ?? EMPTY_ALERT.file_path),
    file_hash: String(payload?.file_hash ?? EMPTY_ALERT.file_hash),
    parent_process: String(payload?.parent_process ?? EMPTY_ALERT.parent_process),
    command_line: String(payload?.command_line ?? EMPTY_ALERT.command_line),
    destination_ip: String(payload?.destination_ip ?? EMPTY_ALERT.destination_ip),
    severity: normalizeRiskLevel(payload?.severity),
    detection_name: String(payload?.detection_name ?? EMPTY_ALERT.detection_name),
    received_at:
      typeof payload?.received_at === "string" && payload.received_at.trim().length > 0 ? payload.received_at : undefined,
  };
}

function normalizeStringList(payload: unknown): string[] {
  return Array.isArray(payload) ? payload.map((item) => String(item)) : [];
}

function normalizeNumberRecord(payload: unknown): Record<string, number> {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(payload).flatMap(([key, value]) => (typeof value === "number" ? [[key, value]] : [])),
  );
}

function normalizeObjectRecord(payload: unknown): Record<string, unknown> {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return {};
  }
  return payload as Record<string, unknown>;
}

function normalizeRiskBreakdown(payload: unknown): RiskBreakdown {
  const record = normalizeObjectRecord(payload);
  const normalizeComponent = (value: unknown) =>
    value && typeof value === "object" && !Array.isArray(value)
      ? {
          raw: Number((value as Record<string, unknown>).raw ?? 0),
          contribution: Number((value as Record<string, unknown>).contribution ?? 0),
        }
      : undefined;

  return {
    hash: normalizeComponent(record.hash),
    ip: normalizeComponent(record.ip),
    asset: normalizeComponent(record.asset),
    severity: normalizeComponent(record.severity),
    mitre: normalizeComponent(record.mitre),
    total: typeof record.total === "number" ? record.total : undefined,
    risk_level: typeof record.risk_level === "string" ? record.risk_level : undefined,
    reasoning: normalizeStringList(record.reasoning),
  };
}

function normalizeHashEnrichment(payload: any): HashEnrichment | undefined {
  if (!payload || typeof payload !== "object") {
    return undefined;
  }

  return {
    hash_value: typeof payload.hash_value === "string" ? payload.hash_value : undefined,
    reputation: String(payload.reputation ?? "unknown").toLowerCase() as HashEnrichment["reputation"],
    malicious_vendors: Number(payload.malicious_vendors ?? 0),
    suspicious_vendors: Number(payload.suspicious_vendors ?? 0),
    harmless_vendors: Number(payload.harmless_vendors ?? 0),
    undetected_vendors: Number(payload.undetected_vendors ?? 0),
    total_vendors: Number(payload.total_vendors ?? 0),
    threat_name: typeof payload.threat_name === "string" ? payload.threat_name : null,
    meaningful_name: typeof payload.meaningful_name === "string" ? payload.meaningful_name : null,
    community_reputation: typeof payload.community_reputation === "number" ? payload.community_reputation : null,
    tags: normalizeStringList(payload.tags),
    analysis_stats: normalizeNumberRecord(payload.analysis_stats),
    last_analysis_date:
      typeof payload.last_analysis_date === "string" && payload.last_analysis_date.trim().length > 0
        ? payload.last_analysis_date
        : null,
    permalink: typeof payload.permalink === "string" && payload.permalink.trim().length > 0 ? payload.permalink : null,
    source: String(payload.source ?? "unknown"),
  };
}

function normalizeIpEnrichment(payload: any): IPEnrichment | undefined {
  if (!payload || typeof payload !== "object") {
    return undefined;
  }

  return {
    ip_address: String(payload.ip_address ?? ""),
    reputation: String(payload.reputation ?? "unknown").toLowerCase() as IPEnrichment["reputation"],
    confidence_score: Number(payload.confidence_score ?? 0),
    is_c2: Boolean(payload.is_c2),
    country: typeof payload.country === "string" ? payload.country : null,
    isp: typeof payload.isp === "string" ? payload.isp : null,
    asn: typeof payload.asn === "number" ? payload.asn : null,
    network: typeof payload.network === "string" ? payload.network : null,
    malicious_vendors: Number(payload.malicious_vendors ?? 0),
    suspicious_vendors: Number(payload.suspicious_vendors ?? 0),
    harmless_vendors: Number(payload.harmless_vendors ?? 0),
    undetected_vendors: Number(payload.undetected_vendors ?? 0),
    tags: normalizeStringList(payload.tags),
    analysis_stats: normalizeNumberRecord(payload.analysis_stats),
    community_reputation: typeof payload.community_reputation === "number" ? payload.community_reputation : null,
    last_analysis_date:
      typeof payload.last_analysis_date === "string" && payload.last_analysis_date.trim().length > 0
        ? payload.last_analysis_date
        : null,
    permalink: typeof payload.permalink === "string" && payload.permalink.trim().length > 0 ? payload.permalink : null,
    source: String(payload.source ?? "unknown"),
  };
}

function normalizeEnrichedAlert(payload: any, fallback: MalwareAlert): EnrichedAlert {
  const originalAlert = normalizeAlert(payload?.original_alert ?? fallback);

  return {
    original_alert: originalAlert,
    hash_enrichment: normalizeHashEnrichment(payload?.hash_enrichment),
    ip_enrichment: normalizeIpEnrichment(payload?.ip_enrichment),
    asset_criticality: normalizeAssetCriticality(payload?.asset_criticality),
    asset_info: normalizeObjectRecord(payload?.asset_info),
    mitre_mappings: Array.isArray(payload?.mitre_mappings)
      ? payload.mitre_mappings.map((mapping: any) => ({
          technique_id: String(mapping?.technique_id ?? ""),
          technique_name: String(mapping?.technique_name ?? ""),
          tactic: String(mapping?.tactic ?? ""),
          matched_pattern: String(mapping?.matched_pattern ?? ""),
          confidence: Number(mapping?.confidence ?? 0),
        }))
      : [],
    risk_score: Number(payload?.risk_score ?? 0),
    risk_level: normalizeRiskLevel(payload?.risk_level),
    risk_breakdown: normalizeRiskBreakdown(payload?.risk_breakdown),
    enriched_at: String(payload?.enriched_at ?? new Date().toISOString()),
  };
}

function normalizeActionStatus(value: unknown): ActionExecutionStatus {
  const status = String(value ?? "succeeded").toLowerCase();
  if (status === "success") {
    return "succeeded";
  }
  if (status === "pending_approval" || status === "blocked_on_approval") {
    return "waiting_approval";
  }
  if (
    status === "queued" ||
    status === "waiting_approval" ||
    status === "running" ||
    status === "succeeded" ||
    status === "failed" ||
    status === "skipped"
  ) {
    return status;
  }
  return "succeeded";
}

function normalizeApprovalState(value: unknown): ActionApprovalState {
  const candidate = String(value ?? "not_required").toLowerCase();
  if (candidate === "pending" || candidate === "approved" || candidate === "rejected" || candidate === "not_required") {
    return candidate;
  }
  return "not_required";
}

function normalizeIncidentCaseStatus(value: unknown): IncidentCaseStatus {
  const candidate = String(value ?? "new").toLowerCase();
  if (
    candidate === "new" ||
    candidate === "triaged" ||
    candidate === "in_progress" ||
    candidate === "monitoring" ||
    candidate === "resolved" ||
    candidate === "closed"
  ) {
    return candidate;
  }
  return "new";
}

function normalizeActionResult(payload: any): ActionResult {
  return {
    action: String(payload?.action ?? "unknown"),
    status: normalizeActionStatus(payload?.status),
    executed_at: String(payload?.executed_at ?? new Date().toISOString()),
    details: String(payload?.details ?? ""),
    correlation_id:
      typeof payload?.correlation_id === "string" && payload.correlation_id.trim().length > 0
        ? payload.correlation_id
        : null,
    attempt_count: Number(payload?.attempt_count ?? 0),
    updated_at: String(payload?.updated_at ?? payload?.executed_at ?? new Date().toISOString()),
    requires_approval: Boolean(payload?.requires_approval),
    approval_state: normalizeApprovalState(payload?.approval_state),
    approval_reason:
      typeof payload?.approval_reason === "string" && payload.approval_reason.trim().length > 0
        ? payload.approval_reason
        : null,
    approved_by:
      typeof payload?.approved_by === "string" && payload.approved_by.trim().length > 0
        ? payload.approved_by
        : null,
    approved_at:
      typeof payload?.approved_at === "string" && payload.approved_at.trim().length > 0 ? payload.approved_at : null,
    operator: typeof payload?.operator === "string" && payload.operator.trim().length > 0 ? payload.operator : null,
  };
}

function summarizeActionCounts(actionResults: ActionResult[]) {
  const queued_action_count = actionResults.filter((action) => action.status === "queued").length;
  const pending_approval_count = actionResults.filter((action) => action.status === "waiting_approval").length;
  const running_action_count = actionResults.filter((action) => action.status === "running").length;
  const failed_action_count = actionResults.filter((action) => action.status === "failed").length;
  const succeeded_action_count = actionResults.filter((action) => action.status === "succeeded").length;
  return {
    queued_action_count,
    pending_approval_count,
    running_action_count,
    failed_action_count,
    succeeded_action_count,
    active_action_count: queued_action_count + pending_approval_count + running_action_count,
  };
}

function normalizeCorrelationHook(payload: any) {
  return {
    field: String(payload?.field ?? ""),
    value: String(payload?.value ?? ""),
  };
}

function normalizeQueuedActionRequest(payload: any): QueuedActionRequest {
  return {
    action: String(payload?.action ?? "unknown"),
    queue_name: String(payload?.queue_name ?? ""),
    correlation_id: String(payload?.correlation_id ?? ""),
    deduplication_key: String(payload?.deduplication_key ?? ""),
    correlation_hooks: Array.isArray(payload?.correlation_hooks)
      ? payload.correlation_hooks.map(normalizeCorrelationHook)
      : [],
    payload: normalizeObjectRecord(payload?.payload),
    requires_approval: Boolean(payload?.requires_approval),
    approval_state: normalizeApprovalState(payload?.approval_state),
    approval_reason:
      typeof payload?.approval_reason === "string" && payload.approval_reason.trim().length > 0
        ? payload.approval_reason
        : null,
    approved_by:
      typeof payload?.approved_by === "string" && payload.approved_by.trim().length > 0 ? payload.approved_by : null,
    approved_at:
      typeof payload?.approved_at === "string" && payload.approved_at.trim().length > 0 ? payload.approved_at : null,
    requested_at:
      typeof payload?.requested_at === "string" && payload.requested_at.trim().length > 0 ? payload.requested_at : undefined,
  };
}

function normalizeIncidentNote(payload: any): IncidentNote {
  return {
    note_id: String(payload?.note_id ?? ""),
    author: String(payload?.author ?? ""),
    body: String(payload?.body ?? ""),
    created_at: String(payload?.created_at ?? new Date().toISOString()),
    updated_at: String(payload?.updated_at ?? payload?.created_at ?? new Date().toISOString()),
  };
}

function normalizeIncidentAuditEvent(payload: any): IncidentAuditEvent {
  return {
    event_id: String(payload?.event_id ?? ""),
    category: String(payload?.category ?? ""),
    actor: String(payload?.actor ?? ""),
    message: String(payload?.message ?? ""),
    payload: normalizeObjectRecord(payload?.payload),
    created_at: String(payload?.created_at ?? new Date().toISOString()),
  };
}

function normalizeExecutionTrace(payload: any): ExecutionTrace {
  return {
    configured_mode: String(payload?.configured_mode ?? "sync"),
    effective_mode: String(payload?.effective_mode ?? "sync"),
    queue_name:
      typeof payload?.queue_name === "string" && payload.queue_name.trim().length > 0 ? payload.queue_name : null,
    fallback_reason:
      typeof payload?.fallback_reason === "string" && payload.fallback_reason.trim().length > 0
        ? payload.fallback_reason
        : null,
    queued_actions: Array.isArray(payload?.queued_actions)
      ? payload.queued_actions.map(normalizeQueuedActionRequest)
      : [],
  };
}

function normalizeReportArtifacts(payload: any, fallbackReportPath: unknown): ReportArtifacts {
  const reportPath =
    typeof fallbackReportPath === "string" && fallbackReportPath.trim().length > 0 ? fallbackReportPath : null;
  return {
    markdown_path:
      typeof payload?.markdown_path === "string" && payload.markdown_path.trim().length > 0 ? payload.markdown_path : null,
    html_path:
      typeof payload?.html_path === "string" && payload.html_path.trim().length > 0 ? payload.html_path : reportPath,
    pdf_path: typeof payload?.pdf_path === "string" && payload.pdf_path.trim().length > 0 ? payload.pdf_path : null,
    markdown_content:
      typeof payload?.markdown_content === "string" && payload.markdown_content.trim().length > 0
        ? payload.markdown_content
        : null,
  };
}

function headers(token: string): HeadersInit {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

function publicErrorMessage(path: string, status: number): string {
  if (status === 401 || status === 403) {
    return "Authentication failed for this dashboard session. Update the bearer token and try again.";
  }

  if (status === 404) {
    return "The requested dashboard resource was not found.";
  }

  if (status === 400 || status === 422) {
    if (path.includes("/incidents/process")) {
      return "The alert payload could not be processed. Review the request and try again.";
    }
    return "The dashboard request was rejected. Review the request and try again.";
  }

  if (status >= 500) {
    return "The dashboard service is temporarily unavailable. Please try again shortly.";
  }

  return "The dashboard request failed. Please try again.";
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  ensureApiAvailable();
  const token = getStoredDashboardAuthToken();
  if (token.length === 0) {
    throw new Error("Paste a bearer token to unlock this dashboard session.");
  }

  const requestHeaders = new Headers(init?.headers);
  Object.entries(headers(token)).forEach(([key, value]) => {
    requestHeaders.set(key, value);
  });

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: requestHeaders,
      credentials: "include",
    });
  } catch {
    throw new Error("The dashboard could not reach the SOAR API. Start the backend, worker, and frontend proxy, then reload.");
  }

  if (!response.ok) {
    throw new Error(publicErrorMessage(path, response.status));
  }

  return response;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await request(path, init);

  return (await response.json()) as T;
}

function normalizeIncidentRecord(payload: any): IncidentRecord {
  const rawEnriched = payload.enriched_alert ?? payload.response?.enriched_alert;
  const alert = normalizeAlert(payload.alert ?? rawEnriched?.original_alert ?? fallbackAlert());
  const enriched = normalizeEnrichedAlert(rawEnriched, alert);
  const responsePayload = payload.response ?? {};
  const completedAt = String(payload.completed_at ?? responsePayload.completed_at ?? new Date().toISOString());
  const actionResults: ActionResult[] = Array.isArray(payload.action_results ?? responsePayload.action_results)
    ? (payload.action_results ?? responsePayload.action_results).map(normalizeActionResult)
    : [];
  const actionCounts = summarizeActionCounts(actionResults);
  const triggeredActions = normalizeStringList(payload.triggered_actions ?? responsePayload.triggered_actions);
  const policyReasoning = normalizeStringList(payload.policy_reasoning ?? responsePayload.policy_reasoning);
  const response = {
    enriched_alert: enriched,
    triggered_actions: triggeredActions,
    policy_reasoning: policyReasoning,
    action_results: actionResults,
    ticket_id: payload.ticket_id ?? responsePayload.ticket_id ?? null,
    completed_at: completedAt,
    report_path: payload.report_path ?? responsePayload.report_path ?? null,
    execution_trace: normalizeExecutionTrace(responsePayload.execution_trace),
  };
  const report = normalizeReportArtifacts(payload.report, response.report_path);

  return {
    id: Number(payload.id ?? 0),
    alert_id: String(payload.alert_id ?? alert.alert_id ?? ""),
    hostname: String(payload.hostname ?? alert.hostname ?? ""),
    detection_name: String(payload.detection_name ?? alert.detection_name ?? ""),
    risk_score: Number(payload.risk_score ?? enriched.risk_score ?? 0),
    risk_level: normalizeRiskLevel(payload.risk_level ?? enriched.risk_level),
    severity: alert.severity,
    process_name: alert.process_name,
    destination_ip: alert.destination_ip,
    ticket_id: payload.ticket_id ?? payload.response?.ticket_id ?? null,
    status: String(payload.status ?? "completed"),
    completed_at: completedAt,
    report_path: response.report_path,
    case_status: normalizeIncidentCaseStatus(payload?.case_status),
    case_owner:
      typeof payload?.case_owner === "string" && payload.case_owner.trim().length > 0 ? payload.case_owner : null,
    queued_action_count: Number(payload?.queued_action_count ?? actionCounts.queued_action_count),
    pending_approval_count: Number(
      payload?.pending_approval_count ??
        actionResults.filter((action) => action.status === "waiting_approval").length,
    ),
    running_action_count: Number(payload?.running_action_count ?? actionCounts.running_action_count),
    failed_action_count: Number(payload?.failed_action_count ?? actionCounts.failed_action_count),
    succeeded_action_count: Number(payload?.succeeded_action_count ?? actionCounts.succeeded_action_count),
    active_action_count: Number(payload?.active_action_count ?? actionCounts.active_action_count),
    note_count: Number(payload?.note_count ?? (Array.isArray(payload?.notes) ? payload.notes.length : 0)),
    triggered_actions: triggeredActions,
    policy_reasoning: policyReasoning,
    action_results: actionResults,
    created_at: String(payload.created_at ?? completedAt),
    updated_at: String(payload.updated_at ?? completedAt),
    alert,
    response,
    report,
    enriched_alert: enriched,
    notes: Array.isArray(payload?.notes) ? payload.notes.map(normalizeIncidentNote) : [],
    audit_events: Array.isArray(payload?.audit_events) ? payload.audit_events.map(normalizeIncidentAuditEvent) : [],
  };
}

function normalizeIncidentSummary(payload: any): IncidentSummary {
  return {
    id: Number(payload.id ?? 0),
    alert_id: String(payload.alert_id ?? ""),
    hostname: String(payload.hostname ?? ""),
    detection_name: String(payload.detection_name ?? ""),
    risk_score: Number(payload.risk_score ?? 0),
    risk_level: normalizeRiskLevel(payload.risk_level),
    severity: payload?.severity ? normalizeRiskLevel(payload.severity) : undefined,
    process_name: typeof payload?.process_name === "string" ? payload.process_name : undefined,
    destination_ip: typeof payload?.destination_ip === "string" ? payload.destination_ip : undefined,
    ticket_id: payload.ticket_id ?? null,
    status: String(payload.status ?? "completed"),
    completed_at: String(payload.completed_at ?? new Date().toISOString()),
    report_path: payload.report_path ?? null,
    case_status: normalizeIncidentCaseStatus(payload?.case_status),
    case_owner: typeof payload?.case_owner === "string" ? payload.case_owner : null,
    queued_action_count: Number(payload?.queued_action_count ?? 0),
    pending_approval_count: Number(payload?.pending_approval_count ?? 0),
    running_action_count: Number(payload?.running_action_count ?? 0),
    failed_action_count: Number(payload?.failed_action_count ?? 0),
    succeeded_action_count: Number(payload?.succeeded_action_count ?? 0),
    active_action_count: Number(payload?.active_action_count ?? 0),
    note_count: Number(payload?.note_count ?? 0),
  };
}

function normalizeSavedFilter(payload: any): SavedFilter {
  return {
    id: Number(payload?.id ?? 0),
    name: String(payload?.name ?? ""),
    filters: normalizeObjectRecord(payload?.filters),
    created_by: String(payload?.created_by ?? ""),
    created_at: String(payload?.created_at ?? new Date().toISOString()),
    updated_at: String(payload?.updated_at ?? new Date().toISOString()),
  };
}

function normalizeDependencyReadiness(payload: any): DependencyReadiness {
  return {
    name: String(payload?.name ?? ""),
    provider: String(payload?.provider ?? ""),
    status: String(payload?.status ?? "degraded"),
    detail: String(payload?.detail ?? ""),
    meta: normalizeObjectRecord(payload?.meta),
  };
}

function normalizeReadiness(payload: any): ReadinessState {
  return {
    status: String(payload?.status ?? "degraded"),
    dependencies: Array.isArray(payload?.dependencies) ? payload.dependencies.map(normalizeDependencyReadiness) : [],
    queue_metrics: normalizeObjectRecord(payload?.queue_metrics),
  };
}

function normalizeScenarioOption(payload: any): ScenarioOption {
  return {
    value: normalizeScenarioKey(payload?.value),
    label: String(payload?.label ?? "Scenario"),
    description: String(payload?.description ?? ""),
  };
}

function normalizeSampleOption(payload: any): SampleOption {
  return {
    value: String(payload?.value ?? ""),
    label: String(payload?.label ?? "Sample alert"),
    scenario: normalizeScenarioKey(payload?.scenario),
    description: String(payload?.description ?? ""),
  };
}

function normalizeDashboardBootstrap(payload: any): DashboardBootstrap {
  const scenario_options = Array.isArray(payload?.scenario_options)
    ? payload.scenario_options.map(normalizeScenarioOption)
    : fallbackDashboardBootstrap.scenario_options;
  const sample_options = Array.isArray(payload?.sample_options)
    ? payload.sample_options.map(normalizeSampleOption).filter((item: SampleOption) => item.value.length > 0)
    : fallbackDashboardBootstrap.sample_options;
  const sample_alerts = Object.fromEntries(
    Object.entries(payload?.sample_alerts ?? {}).map(([sampleId, alert]) => [sampleId, normalizeAlert(alert)]),
  ) as Record<string, MalwareAlert>;
  const default_sample_id =
    typeof payload?.default_sample_id === "string" && payload.default_sample_id.trim().length > 0
      ? payload.default_sample_id
      : sample_options[0]?.value ?? null;
  const default_scenario = normalizeScenarioKey(payload?.default_scenario);
  const default_json =
    typeof payload?.default_json === "string" && payload.default_json.trim().length > 0
      ? payload.default_json
      : JSON.stringify(sample_alerts[default_sample_id ?? ""] ?? EMPTY_ALERT, null, 2);

  return {
    scenario_options,
    sample_options,
    sample_alerts,
    default_sample_id,
    default_scenario,
    default_json,
  };
}

async function apiOnly<T>(action: () => Promise<T>): Promise<{ mode: ApiMode; data: T }> {
  return { mode: "api", data: await action() };
}

export function getFallbackDashboardBootstrap(): DashboardBootstrap {
  return fallbackDashboardBootstrap;
}

export async function loadDashboardBootstrap(): Promise<{ mode: ApiMode; bootstrap: DashboardBootstrap }> {
  const result = await apiOnly(async () => normalizeDashboardBootstrap(await requestJson<any>("/api/v1/dashboard/bootstrap")));
  return { mode: result.mode, bootstrap: result.data };
}

export async function listIncidents(): Promise<{ mode: ApiMode; incidents: IncidentSummary[] }> {
  const result = await apiOnly(async () => {
    const payload = await requestJson<any[]>("/api/v1/incidents?limit=100");
    return payload.map(normalizeIncidentSummary);
  });
  return { mode: result.mode, incidents: result.data };
}

export async function listSavedFilters(): Promise<{ mode: ApiMode; filters: SavedFilter[] }> {
  const result = await apiOnly(async () => {
    const payload = await requestJson<any[]>("/api/v1/incidents/saved-filters");
    return payload.map(normalizeSavedFilter);
  });
  return { mode: result.mode, filters: result.data };
}

export async function saveFilter(
  name: string,
  createdBy: string,
  filters: Record<string, unknown>,
): Promise<{ mode: ApiMode; filter: SavedFilter }> {
  const result = await apiOnly(async () => {
    const payload = await requestJson<any>("/api/v1/incidents/saved-filters", {
      method: "POST",
      body: JSON.stringify({ name, created_by: createdBy, filters }),
    });
    return normalizeSavedFilter(payload);
  });
  return { mode: result.mode, filter: result.data };
}

export async function getIncident(alertId: string): Promise<{ mode: ApiMode; incident: IncidentRecord | null }> {
  const result = await apiOnly(async () => {
    const payload = await requestJson<any>(`/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}?include_sensitive=true`);
    return normalizeIncidentRecord(payload);
  });
  return { mode: result.mode, incident: result.data };
}

export async function updateIncidentCase(
  alertId: string,
  payload: { case_status?: string; case_owner?: string; comment?: string },
): Promise<{ mode: ApiMode; incident: IncidentRecord }> {
  const result = await apiOnly(async () => {
    const response = await requestJson<any>(`/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    return normalizeIncidentRecord(response);
  });
  return { mode: result.mode, incident: result.data };
}

export async function addIncidentNote(
  alertId: string,
  payload: { author: string; body: string },
): Promise<{ mode: ApiMode; note: IncidentNote }> {
  const result = await apiOnly(async () => {
    const response = await requestJson<any>(`/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}/notes`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return normalizeIncidentNote(response);
  });
  return { mode: result.mode, note: result.data };
}

export async function bulkUpdateIncidents(payload: {
  alert_ids: string[];
  case_status?: string;
  case_owner?: string;
  comment?: string;
}): Promise<{ mode: ApiMode; incidents: IncidentRecord[] }> {
  const result = await apiOnly(async () => {
    const response = await requestJson<any[]>("/api/v1/incidents/bulk-update", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    return response.map(normalizeIncidentRecord);
  });
  return { mode: result.mode, incidents: result.data };
}

export async function approveAction(
  alertId: string,
  correlationId: string,
  payload: { actor: string; comment?: string },
): Promise<{ mode: ApiMode; incident: IncidentRecord }> {
  const result = await apiOnly(async () => {
    const response = await requestJson<any>(
      `/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}/actions/${encodeURIComponent(correlationId)}/approve`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
    return normalizeIncidentRecord(response);
  });
  return { mode: result.mode, incident: result.data };
}

export async function rejectAction(
  alertId: string,
  correlationId: string,
  payload: { actor: string; comment?: string },
): Promise<{ mode: ApiMode; incident: IncidentRecord }> {
  const result = await apiOnly(async () => {
    const response = await requestJson<any>(
      `/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}/actions/${encodeURIComponent(correlationId)}/reject`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
    return normalizeIncidentRecord(response);
  });
  return { mode: result.mode, incident: result.data };
}

export async function getReadiness(): Promise<{ mode: ApiMode; readiness: ReadinessState }> {
  const result = await apiOnly(async () => normalizeReadiness(await requestJson<any>("/api/v1/ready")));
  return { mode: result.mode, readiness: result.data };
}

export async function processAlert(
  input: ProcessAlertInput,
  bootstrap: DashboardBootstrap,
): Promise<{ mode: ApiMode; incident: IncidentRecord }> {
  const result = await apiOnly(async () => {
    if (input.mode === "scenario") {
      const payload = await requestJson<any>("/api/v1/incidents/process-scenario", {
        method: "POST",
        body: JSON.stringify({
          scenario: input.scenario,
          seed: 2024,
          generate_report: true,
          export_pdf: false,
        }),
      });
      const alertId = payload.response.enriched_alert.original_alert.alert_id;
      const detail = await requestJson<any>(`/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}?include_sensitive=true`);
      return normalizeIncidentRecord(detail);
    }

    let alert: MalwareAlert | undefined;
    if (input.mode === "sample") {
      alert = bootstrap.sample_alerts[input.sampleId];
    } else {
      alert = normalizeAlert(JSON.parse(input.rawJson));
    }

    if (!alert) {
      if (input.mode === "sample") {
        throw new Error("The selected sample alert is unavailable.");
      }
      throw new Error("Unable to parse the provided alert payload.");
    }

    const payload = await requestJson<any>("/api/v1/incidents/process", {
      method: "POST",
      body: JSON.stringify({
        alert,
        generate_report: true,
        export_pdf: false,
      }),
    });
    const alertId = payload.response.enriched_alert.original_alert.alert_id;
    const detail = await requestJson<any>(`/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}?include_sensitive=true`);
    return normalizeIncidentRecord(detail);
  });

  return { mode: result.mode, incident: result.data };
}

export async function openIncidentReport(alertId: string): Promise<void> {
  if (typeof window === "undefined") {
    return;
  }

  const reportWindow = window.open("", "_blank");
  if (reportWindow) {
    reportWindow.document.title = "Loading SOAR report";
    reportWindow.document.body.innerHTML = "<p>Loading report...</p>";
  }

  try {
    const response = await request(`/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}/report/html`);
    const html = await response.text();

    if (reportWindow) {
      try {
        reportWindow.opener = null;
      } catch {
      }
      reportWindow.document.open();
      reportWindow.document.write(html);
      reportWindow.document.close();
      return;
    }

    const blobUrl = window.URL.createObjectURL(new Blob([html], { type: "text/html" }));
    window.open(blobUrl, "_blank", "noopener");
    window.setTimeout(() => window.URL.revokeObjectURL(blobUrl), 60_000);
  } catch (error) {
    reportWindow?.close();
    throw error;
  }
}

export { API_BASE_URL };
