import {
  getDefaultJson,
  getMockIncident,
  getSampleAlert,
  listMockIncidents,
  processMockAlert,
  sampleOptions,
  scenarioOptions,
} from "../data/mockIncidents";
import type {
  ActionResult,
  ApiMode,
  CorrelationHook,
  DashboardBootstrap,
  ExecutionTrace,
  IncidentRecord,
  IncidentSummary,
  MalwareAlert,
  ProcessAlertInput,
  QueuedActionRequest,
  ReportArtifacts,
  RiskLevel,
  SampleOption,
  ScenarioKey,
  ScenarioOption,
} from "../types";

const EXPLICIT_API_BASE_URL = (import.meta.env.VITE_SOAR_API_BASE_URL ?? "").trim().replace(/\/$/, "");
const DEV_PROXY_BASE_URL = import.meta.env.DEV ? "/soar-api" : "";
const API_BASE_URL = (EXPLICIT_API_BASE_URL || DEV_PROXY_BASE_URL).replace(/\/$/, "");

function canUseApi(): boolean {
  return API_BASE_URL.length > 0;
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

function fallbackAlert(): MalwareAlert {
  return {
    alert_id: "unknown-alert",
    hostname: "Unknown host",
    username: "unknown",
    process_name: "unknown",
    file_path: "unknown",
    file_hash: "unknown",
    parent_process: "unknown",
    command_line: "unknown",
    destination_ip: "0.0.0.0",
    severity: "medium",
    detection_name: "Unknown detection",
  };
}

function normalizeAlert(payload: any): MalwareAlert {
  return {
    alert_id: String(payload?.alert_id ?? "unknown-alert"),
    hostname: String(payload?.hostname ?? "Unknown host"),
    username: String(payload?.username ?? "unknown"),
    process_name: String(payload?.process_name ?? "unknown"),
    file_path: String(payload?.file_path ?? "unknown"),
    file_hash: String(payload?.file_hash ?? "unknown"),
    parent_process: String(payload?.parent_process ?? "unknown"),
    command_line: String(payload?.command_line ?? "unknown"),
    destination_ip: String(payload?.destination_ip ?? "0.0.0.0"),
    severity: normalizeRiskLevel(payload?.severity),
    detection_name: String(payload?.detection_name ?? "Unknown detection"),
  };
}

function normalizeStringList(payload: unknown): string[] {
  return Array.isArray(payload) ? payload.map((item) => String(item)) : [];
}

function normalizeActionResult(payload: any): ActionResult {
  const status = String(payload?.status ?? "success").toLowerCase();
  return {
    action: String(payload?.action ?? "unknown"),
    status:
      status === "failed" || status === "queued" || status === "skipped" || status === "success"
        ? status
        : "success",
    executed_at: String(payload?.executed_at ?? new Date().toISOString()),
    details: String(payload?.details ?? ""),
  };
}

function normalizeCorrelationHook(payload: any): CorrelationHook {
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
    payload:
      payload?.payload && typeof payload.payload === "object" && !Array.isArray(payload.payload)
        ? payload.payload
        : {},
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
      typeof payload?.html_path === "string" && payload.html_path.trim().length > 0
        ? payload.html_path
        : reportPath,
    pdf_path: typeof payload?.pdf_path === "string" && payload.pdf_path.trim().length > 0 ? payload.pdf_path : null,
    markdown_content:
      typeof payload?.markdown_content === "string" && payload.markdown_content.trim().length > 0
        ? payload.markdown_content
        : null,
  };
}

function headers(): HeadersInit {
  return {
    "Content-Type": "application/json",
  };
}

function publicErrorMessage(path: string, status: number): string {
  if (status === 401 || status === 403) {
    return "Authentication is required to access the dashboard service.";
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

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const requestHeaders = new Headers(init?.headers);
  Object.entries(headers()).forEach(([key, value]) => {
    requestHeaders.set(key, value);
  });

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: requestHeaders,
    credentials: "include",
  });

  if (!response.ok) {
    throw new Error(publicErrorMessage(path, response.status));
  }

  return (await response.json()) as T;
}

function normalizeIncidentRecord(payload: any): IncidentRecord {
  const enriched = payload.enriched_alert ?? payload.response?.enriched_alert;
  const alert = normalizeAlert(payload.alert ?? enriched?.original_alert ?? fallbackAlert());
  const riskLevel = normalizeRiskLevel(payload.risk_level ?? enriched?.risk_level);
  const responsePayload = payload.response ?? {};
  const completedAt = String(payload.completed_at ?? responsePayload.completed_at ?? new Date().toISOString());
  const actionResults = Array.isArray(payload.action_results ?? responsePayload.action_results)
    ? (payload.action_results ?? responsePayload.action_results).map(normalizeActionResult)
    : [];
  const triggeredActions = normalizeStringList(payload.triggered_actions ?? responsePayload.triggered_actions);
  const policyReasoning = normalizeStringList(payload.policy_reasoning ?? responsePayload.policy_reasoning);
  const response = {
    enriched_alert: enriched ?? responsePayload.enriched_alert,
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
    risk_score: Number(payload.risk_score ?? enriched?.risk_score ?? 0),
    risk_level: riskLevel,
    ticket_id: payload.ticket_id ?? payload.response?.ticket_id ?? null,
    status: String(payload.status ?? "completed"),
    completed_at: completedAt,
    report_path: response.report_path,
    triggered_actions: triggeredActions,
    policy_reasoning: policyReasoning,
    action_results: actionResults,
    created_at: String(payload.created_at ?? completedAt),
    updated_at: String(payload.updated_at ?? completedAt),
    alert,
    response,
    report,
    enriched_alert: enriched ?? response.enriched_alert,
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
    ticket_id: payload.ticket_id ?? null,
    status: String(payload.status ?? "completed"),
    completed_at: String(payload.completed_at ?? new Date().toISOString()),
    report_path: payload.report_path ?? null,
  };
}

function buildFallbackDashboardBootstrap(): DashboardBootstrap {
  const sampleAlerts = Object.fromEntries(
    sampleOptions.map((option) => [option.value, getSampleAlert(option.value)]),
  ) as Record<string, MalwareAlert>;

  return {
    scenario_options: scenarioOptions,
    sample_options: sampleOptions,
    sample_alerts: sampleAlerts,
    default_sample_id: sampleOptions[0]?.value ?? null,
    default_scenario: "mixed",
    default_json: getDefaultJson(),
  };
}

const fallbackDashboardBootstrap = buildFallbackDashboardBootstrap();

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
    typeof payload?.default_sample_id === "string" && payload.default_sample_id.trim()
      ? payload.default_sample_id
      : sample_options[0]?.value ?? fallbackDashboardBootstrap.default_sample_id ?? null;
  const default_scenario = normalizeScenarioKey(payload?.default_scenario);
  const default_json =
    typeof payload?.default_json === "string" && payload.default_json.trim()
      ? payload.default_json
      : JSON.stringify(sample_alerts[default_sample_id ?? ""] ?? fallbackAlert(), null, 2);

  return {
    scenario_options,
    sample_options,
    sample_alerts: Object.keys(sample_alerts).length > 0 ? sample_alerts : fallbackDashboardBootstrap.sample_alerts,
    default_sample_id,
    default_scenario,
    default_json,
  };
}

async function withPreferredSource<T>(action: () => Promise<T>, fallback: () => T): Promise<{ mode: ApiMode; data: T }> {
  if (!canUseApi()) {
    return { mode: "mock", data: fallback() };
  }

  return { mode: "api", data: await action() };
}

export function getFallbackDashboardBootstrap(): DashboardBootstrap {
  return fallbackDashboardBootstrap;
}

export async function loadDashboardBootstrap(): Promise<{ mode: ApiMode; bootstrap: DashboardBootstrap }> {
  const result = await withPreferredSource(
    async () => normalizeDashboardBootstrap(await requestJson<any>("/api/v1/dashboard/bootstrap")),
    () => fallbackDashboardBootstrap,
  );

  return { mode: result.mode, bootstrap: result.data };
}

export async function listIncidents(): Promise<{ mode: ApiMode; incidents: IncidentSummary[] }> {
  const result = await withPreferredSource(
    async () => {
      const payload = await requestJson<any[]>("/api/v1/incidents?limit=100");
      return payload.map(normalizeIncidentSummary);
    },
    () => listMockIncidents(),
  );

  return { mode: result.mode, incidents: result.data };
}

export async function getIncident(alertId: string): Promise<{ mode: ApiMode; incident: IncidentRecord | null }> {
  const result = await withPreferredSource(
    async () => {
      const payload = await requestJson<any>(
        `/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}?include_sensitive=true`,
      );
      return normalizeIncidentRecord(payload);
    },
    () => getMockIncident(alertId),
  );

  return { mode: result.mode, incident: result.data };
}

export async function processAlert(
  input: ProcessAlertInput,
  bootstrap: DashboardBootstrap,
): Promise<{ mode: ApiMode; incident: IncidentRecord }> {
  const result = await withPreferredSource(
    async () => {
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
        const detail = await requestJson<any>(
          `/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}?include_sensitive=true`,
        );
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
      const detail = await requestJson<any>(
        `/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}?include_sensitive=true`,
      );
      return normalizeIncidentRecord(detail);
    },
    () => processMockAlert(input),
  );

  return { mode: result.mode, incident: result.data };
}

export function buildIncidentReportUrl(alertId: string): string | null {
  if (!canUseApi()) {
    return null;
  }
  return `${API_BASE_URL}/api/v1/incidents/by-alert/${encodeURIComponent(alertId)}/report/html`;
}

export { API_BASE_URL };
