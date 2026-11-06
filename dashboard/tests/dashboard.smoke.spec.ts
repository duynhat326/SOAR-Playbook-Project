import { expect, test, type Page } from "@playwright/test";

const bootstrapPayload = {
  scenario_options: [
    { value: "mixed", label: "Mixed chain", description: "Exercise the full SOAR path." },
  ],
  sample_options: [
    { value: "sample-1", label: "Sample alert", scenario: "mixed", description: "Bundled smoke-test alert." },
  ],
  sample_alerts: {
    "sample-1": {
      alert_id: "smoke-alert-1",
      hostname: "WS-SMOKE-01",
      username: "analyst",
      process_name: "powershell.exe",
      file_path: "C:\\Temp\\payload.ps1",
      file_hash: "44d88612fea8a8f36de82e1278abb02f",
      parent_process: "explorer.exe",
      command_line: "powershell.exe -enc SGVsbG8=",
      destination_ip: "185.220.101.45",
      severity: "high",
      detection_name: "Malware.Powershell.Encoded",
    },
  },
  default_sample_id: "sample-1",
  default_scenario: "mixed",
  default_json: JSON.stringify({
    alert_id: "smoke-alert-1",
    hostname: "WS-SMOKE-01",
  }),
};

const incidentSummaryPayload = [
  {
    id: 1,
    alert_id: "smoke-alert-1",
    hostname: "WS-SMOKE-01",
    detection_name: "Malware.Powershell.Encoded",
    risk_score: 88.2,
    risk_level: "critical",
    ticket_id: "INC-20260703-0001",
    status: "pending_approval",
    completed_at: "2026-07-03T07:00:00Z",
    report_path: "output/reports/smoke-alert-1.html",
    case_status: "triaged",
    case_owner: "SOC Team",
    queued_action_count: 0,
    pending_approval_count: 1,
    running_action_count: 0,
    failed_action_count: 0,
    succeeded_action_count: 2,
    active_action_count: 1,
    note_count: 1,
  },
];

const incidentDetailPayload = {
  ...incidentSummaryPayload[0],
  triggered_actions: ["isolate_host", "create_ticket", "notify_soc"],
  policy_reasoning: ["Hash matched a malicious family.", "Host containment requires analyst approval."],
  action_results: [
    {
      action: "isolate_host",
      status: "waiting_approval",
      executed_at: "2026-07-03T07:00:00Z",
      details: "Queued 'isolate_host' pending analyst approval.",
      correlation_id: "policy:smoke-alert-1:isolate_host",
      attempt_count: 0,
      updated_at: "2026-07-03T07:00:00Z",
      requires_approval: true,
      approval_state: "pending",
      approval_reason: "Host isolation impacts endpoint connectivity.",
      approved_by: null,
      approved_at: null,
      operator: null,
    },
    {
      action: "create_ticket",
      status: "succeeded",
      executed_at: "2026-07-03T07:00:00Z",
      details: "Ticket [INC-20260703-0001] created with priority P1.",
      correlation_id: null,
      attempt_count: 0,
      updated_at: "2026-07-03T07:00:00Z",
      requires_approval: false,
      approval_state: "not_required",
      approval_reason: null,
      approved_by: null,
      approved_at: null,
      operator: "SOAR_AUTO",
    },
  ],
  created_at: "2026-07-03T06:58:00Z",
  updated_at: "2026-07-03T07:00:00Z",
  alert: bootstrapPayload.sample_alerts["sample-1"],
  response: {
    enriched_alert: {
      original_alert: bootstrapPayload.sample_alerts["sample-1"],
      hash_enrichment: {
        hash_value: "44d88612fea8a8f36de82e1278abb02f",
        reputation: "malicious",
        malicious_vendors: 64,
        suspicious_vendors: 0,
        harmless_vendors: 1,
        undetected_vendors: 9,
        total_vendors: 74,
        threat_name: "virus.eicar/test",
        meaningful_name: "eicar.com",
        community_reputation: -12,
        tags: ["eicar", "test"],
        analysis_stats: { malicious: 64, harmless: 1, undetected: 9 },
        last_analysis_date: "2026-07-02T12:00:00Z",
        permalink: "https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f",
        source: "virustotal_api_v3",
      },
      ip_enrichment: {
        ip_address: "185.220.101.45",
        reputation: "malicious",
        confidence_score: 100,
        is_c2: true,
        country: "DE",
        isp: "Tor relay",
        asn: 60729,
        network: "185.220.101.0/24",
        malicious_vendors: 22,
        suspicious_vendors: 0,
        harmless_vendors: 0,
        undetected_vendors: 12,
        tags: ["tor", "c2"],
        analysis_stats: { malicious: 22, undetected: 12 },
        community_reputation: -9,
        last_analysis_date: "2026-07-02T12:00:00Z",
        permalink: "https://www.virustotal.com/gui/ip-address/185.220.101.45",
        source: "virustotal_api_v3",
      },
      asset_criticality: "normal",
      asset_info: { owner: "SOC Team", department: "Blue Team" },
      mitre_mappings: [
        {
          technique_id: "T1059.001",
          technique_name: "PowerShell",
          tactic: "Execution",
          matched_pattern: "encoded PowerShell",
          confidence: 0.91,
        },
      ],
      risk_score: 88.2,
      risk_level: "critical",
      risk_breakdown: {
        hash: { raw: 0.91, contribution: 36.4 },
        ip: { raw: 1, contribution: 25 },
        asset: { raw: 0.5, contribution: 10 },
        severity: { raw: 0.75, contribution: 11.2 },
        mitre: { raw: 0.55, contribution: 5.6 },
        total: 88.2,
        risk_level: "critical",
        reasoning: ["High-confidence file and network telemetry aligned."],
      },
      enriched_at: "2026-07-03T06:59:00Z",
    },
    triggered_actions: ["isolate_host", "create_ticket", "notify_soc"],
    policy_reasoning: ["Hash matched a malicious family.", "Host containment requires analyst approval."],
    action_results: [],
    ticket_id: "INC-20260703-0001",
    completed_at: "2026-07-03T07:00:00Z",
    report_path: "output/reports/smoke-alert-1.html",
    execution_trace: {
      configured_mode: "queued",
      effective_mode: "queued",
      queue_name: "remediation",
      fallback_reason: null,
      queued_actions: [
        {
          action: "isolate_host",
          queue_name: "remediation",
          correlation_id: "policy:smoke-alert-1:isolate_host",
          deduplication_key: "policy:smoke-alert-1:isolate_host",
          correlation_hooks: [{ field: "hostname", value: "WS-SMOKE-01" }],
          payload: { alert_id: "smoke-alert-1", hostname: "WS-SMOKE-01", action: "isolate_host" },
          requires_approval: true,
          approval_state: "pending",
          approval_reason: "Host isolation impacts endpoint connectivity.",
          approved_by: null,
          approved_at: null,
          requested_at: "2026-07-03T07:00:00Z",
        },
      ],
    },
  },
  report: {
    markdown_path: "output/reports/smoke-alert-1.md",
    html_path: "output/reports/smoke-alert-1.html",
    pdf_path: null,
    markdown_content: "## Executive Summary\nApproval is pending before containment runs.",
  },
  enriched_alert: {
    original_alert: bootstrapPayload.sample_alerts["sample-1"],
    hash_enrichment: null,
    ip_enrichment: null,
    asset_criticality: "normal",
    asset_info: {},
    mitre_mappings: [],
    risk_score: 88.2,
    risk_level: "critical",
    risk_breakdown: { reasoning: [] },
    enriched_at: "2026-07-03T06:59:00Z",
  },
  notes: [
    {
      note_id: "note-1",
      author: "SOC Team",
      body: "Waiting on analyst sign-off before isolating the workstation.",
      created_at: "2026-07-03T07:01:00Z",
      updated_at: "2026-07-03T07:01:00Z",
    },
  ],
  audit_events: [
    {
      event_id: "audit-1",
      category: "approval.waiting",
      actor: "queue-publisher",
      message: "Action 'isolate_host' is waiting for analyst approval.",
      payload: {},
      created_at: "2026-07-03T07:00:00Z",
    },
  ],
};

const readinessPayload = {
  status: "ready",
  dependencies: [
    { name: "incident_repository", provider: "sqlite", status: "ready", detail: "Persistence target is local.", meta: {} },
    { name: "threat_intel", provider: "virustotal", status: "ready", detail: "VirusTotal provider is configured.", meta: {} },
  ],
  queue_metrics: { total_jobs: 1, waiting_approval_jobs: 1 },
};

async function installDashboardSessionToken(page: Page) {
  await page.addInitScript(() => {
    window.sessionStorage.setItem("soar.dashboard.authToken", "playwright-session-token");
  });
}

async function mockDashboardApi(page: Page) {
  const context = page.context();
  await context.route("**/api/v1/dashboard/bootstrap", async (route) => {
    await route.fulfill({ json: bootstrapPayload });
  });
  await context.route("**/api/v1/incidents?limit=100", async (route) => {
    await route.fulfill({ json: incidentSummaryPayload });
  });
  await context.route("**/api/v1/incidents/saved-filters", async (route) => {
    if (route.request().method() === "POST") {
      await route.fulfill({
        json: {
          id: 1,
          name: "critical-queue",
          filters: { risk_level: "critical", case_status: "triaged" },
          created_by: "dashboard-analyst",
          created_at: "2026-07-03T07:00:00Z",
          updated_at: "2026-07-03T07:00:00Z",
        },
      });
      return;
    }
    await route.fulfill({ json: [] });
  });
  await context.route("**/api/v1/incidents/by-alert/smoke-alert-1?include_sensitive=true", async (route) => {
    await route.fulfill({ json: incidentDetailPayload });
  });
  await context.route("**/api/v1/ready", async (route) => {
    await route.fulfill({ json: readinessPayload });
  });
  await context.route("**/api/v1/incidents/by-alert/smoke-alert-1/report/html", async (route) => {
    await route.fulfill({
      contentType: "text/html",
      body: "<html><body><h1>Incident Report</h1><p>Smoke report rendered.</p></body></html>",
    });
  });
}

test("dashboard loads incident list and case detail from API contracts", async ({ page }) => {
  await installDashboardSessionToken(page);
  await mockDashboardApi(page);

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Incident stream" })).toBeVisible();
  await expect(page.locator(".topbar-status")).toContainText("Backend connected");
  await expect(page.locator(".detail-panel > .section-head h2")).toHaveText("WS-SMOKE-01");
  await expect(page.locator(".timeline-item p").first()).toHaveText(
    "Waiting on analyst sign-off before isolating the workstation.",
  );
  await expect(page.getByRole("button", { name: "Approve" })).toBeVisible();
});

test("report link opens HTML artifact flow", async ({ page }) => {
  await installDashboardSessionToken(page);
  await mockDashboardApi(page);

  await page.goto("/");

  const reportRequestPromise = page.waitForRequest("**/api/v1/incidents/by-alert/smoke-alert-1/report/html");
  await page.getByRole("tab", { name: "Trace & report" }).click();
  await page.getByRole("button", { name: "Open HTML report" }).click();
  const reportRequest = await reportRequestPromise;
  expect(reportRequest.headers()["authorization"]).toBe("Bearer playwright-session-token");
});
