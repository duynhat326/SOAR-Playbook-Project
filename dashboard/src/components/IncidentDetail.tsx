import { useEffect, useState, type ReactNode } from "react";

import { actionLabel, formatDateTime, formatRiskScore, riskTone, statusLabel, titleCase } from "../lib/format";
import { openIncidentReport } from "../services/soarApi";
import type { IncidentCaseStatus, IncidentRecord, QueuedActionRequest, RiskBreakdownComponent } from "../types";

interface IncidentDetailProps {
  incident: IncidentRecord | null;
  loading: boolean;
  onUpdateCase: (payload: { case_status?: string; case_owner?: string; comment?: string }) => void;
  onAddNote: (body: string) => void;
  onApproveAction: (correlationId: string, comment?: string) => void;
  onRejectAction: (correlationId: string, comment?: string) => void;
  onRollbackAction: (correlationId: string, comment?: string) => void;
  onReopenIncident: (comment?: string) => void;
}

type DetailTab = "response" | "case" | "intel" | "trace" | "audit" | "raw";

const DETAIL_TABS: { id: DetailTab; label: string }[] = [
  { id: "response", label: "Response & approvals" },
  { id: "case", label: "Case" },
  { id: "intel", label: "Threat intel" },
  { id: "trace", label: "Trace & report" },
  { id: "audit", label: "Audit" },
  { id: "raw", label: "Raw data" },
];

function present(value: string | null | undefined, fallback = "Not set"): string {
  return value && value.trim().length > 0 ? value : fallback;
}

function readableTraceValue(value: string | null | undefined, fallback = "Not set"): string {
  return value && value.trim().length > 0 ? titleCase(value.replace(/_/g, " ")) : fallback;
}

function compactValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map(compactValue).filter(Boolean).join(", ");
  }
  return JSON.stringify(value);
}

function summarizeQueuedAction(request: QueuedActionRequest): string {
  const entries = Object.entries(request.payload)
    .map(([key, value]) => [key, compactValue(value)] as const)
    .filter(([, value]) => value.length > 0)
    .slice(0, 5);

  if (entries.length === 0) {
    return "No payload metadata";
  }

  return entries.map(([key, value]) => `${key}=${value}`).join(" | ");
}

function actionStatusTone(status: string): string {
  if (status === "failed") {
    return "tone-critical";
  }
  if (status === "waiting_approval") {
    return "tone-medium";
  }
  if (status === "running") {
    return "tone-sky";
  }
  if (status === "queued" || status === "skipped") {
    return "tone-neutral";
  }
  return "tone-low";
}

function isPastTimestamp(value: string | null | undefined): boolean {
  if (!value) {
    return false;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
}

function renderMarkdownPreview(markdownContent: string): ReactNode {
  const blocks: ReactNode[] = [];
  const lines = markdownContent.replace(/\r\n/g, "\n").split("\n");
  let paragraphLines: string[] = [];
  let listItems: string[] = [];
  let quoteLines: string[] = [];
  let codeLines: string[] = [];
  let inCodeFence = false;

  const flushParagraph = () => {
    if (paragraphLines.length === 0) {
      return;
    }
    blocks.push(<p key={`p-${blocks.length}`}>{paragraphLines.join(" ")}</p>);
    paragraphLines = [];
  };

  const flushList = () => {
    if (listItems.length === 0) {
      return;
    }
    blocks.push(
      <ul key={`ul-${blocks.length}`}>
        {listItems.map((item, index) => (
          <li key={`li-${index}`}>{item}</li>
        ))}
      </ul>,
    );
    listItems = [];
  };

  const flushQuote = () => {
    if (quoteLines.length === 0) {
      return;
    }
    blocks.push(<blockquote key={`quote-${blocks.length}`}>{quoteLines.join(" ")}</blockquote>);
    quoteLines = [];
  };

  const flushCode = () => {
    blocks.push(
      <pre key={`code-${blocks.length}`} className="markdown-code">
        {codeLines.join("\n")}
      </pre>,
    );
    codeLines = [];
  };

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();

    if (trimmed.startsWith("```")) {
      if (inCodeFence) {
        flushCode();
        inCodeFence = false;
      } else {
        flushParagraph();
        flushList();
        flushQuote();
        inCodeFence = true;
      }
      continue;
    }

    if (inCodeFence) {
      codeLines.push(rawLine);
      continue;
    }

    if (trimmed.length === 0) {
      flushParagraph();
      flushList();
      flushQuote();
      continue;
    }

    const headingMatch = /^(#{1,4})\s+(.*)$/.exec(trimmed);
    if (headingMatch) {
      flushParagraph();
      flushList();
      flushQuote();
      const content = headingMatch[2];
      const level = headingMatch[1].length;
      if (level === 1) {
        blocks.push(<h1 key={`h1-${blocks.length}`}>{content}</h1>);
      } else if (level === 2) {
        blocks.push(<h2 key={`h2-${blocks.length}`}>{content}</h2>);
      } else if (level === 3) {
        blocks.push(<h3 key={`h3-${blocks.length}`}>{content}</h3>);
      } else {
        blocks.push(<h4 key={`h4-${blocks.length}`}>{content}</h4>);
      }
      continue;
    }

    if (trimmed.startsWith("> ")) {
      flushParagraph();
      flushList();
      quoteLines.push(trimmed.slice(2));
      continue;
    }

    if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
      flushParagraph();
      flushQuote();
      listItems.push(trimmed.slice(2));
      continue;
    }

    paragraphLines.push(trimmed);
  }

  if (inCodeFence) {
    flushCode();
  }
  flushParagraph();
  flushList();
  flushQuote();

  return <div className="markdown-preview">{blocks}</div>;
}

function renderBreakdownRow(label: string, component?: RiskBreakdownComponent, emphasize = false): ReactNode {
  if (!component) {
    return null;
  }

  return (
    <div className={`breakdown-row ${emphasize ? "is-total" : ""}`} key={label}>
      <span>{label}</span>
      <strong>{component.contribution.toFixed(2)}</strong>
      <small>raw {component.raw.toFixed(3)}</small>
    </div>
  );
}

function renderObjectFacts(values: Record<string, unknown>): ReactNode {
  const entries = Object.entries(values).filter(([, value]) => compactValue(value).length > 0);
  if (entries.length === 0) {
    return (
      <div className="empty-mini">
        <strong>No asset metadata returned.</strong>
        <span>The CMDB lookup did not contribute extra host context for this incident.</span>
      </div>
    );
  }

  return (
    <div className="object-fact-grid">
      {entries.map(([key, value]) => (
        <div className="object-fact" key={key}>
          <span>{key.replace(/_/g, " ")}</span>
          <strong>{compactValue(value)}</strong>
        </div>
      ))}
    </div>
  );
}

function renderTagRow(tags: string[]): ReactNode {
  if (tags.length === 0) {
    return <span className="meta-empty">No tags</span>;
  }

  return (
    <div className="pill-row">
      {tags.map((tag) => (
        <span className="badge tone-neutral" key={tag}>
          {tag}
        </span>
      ))}
    </div>
  );
}

function renderAnalysisStats(stats: Record<string, number>): ReactNode {
  const entries = Object.entries(stats);
  if (entries.length === 0) {
    return <span className="meta-empty">No analysis stats</span>;
  }

  return (
    <div className="pill-row">
      {entries.map(([key, value]) => (
        <span className="badge tone-neutral" key={key}>
          {key}: {value}
        </span>
      ))}
    </div>
  );
}

export function IncidentDetail({
  incident,
  loading,
  onUpdateCase,
  onAddNote,
  onApproveAction,
  onRejectAction,
  onRollbackAction,
  onReopenIncident,
}: IncidentDetailProps) {
  const [caseOwnerDraft, setCaseOwnerDraft] = useState("");
  const [caseStatusDraft, setCaseStatusDraft] = useState<IncidentCaseStatus>("new");
  const [noteDraft, setNoteDraft] = useState("");
  const [reportOpenError, setReportOpenError] = useState<string | null>(null);
  const [openingReport, setOpeningReport] = useState(false);
  const [activeTab, setActiveTab] = useState<DetailTab>("response");

  useEffect(() => {
    setCaseOwnerDraft(incident?.case_owner ?? "");
    setCaseStatusDraft((incident?.case_status ?? "new") as IncidentCaseStatus);
    setNoteDraft("");
    setReportOpenError(null);
    setOpeningReport(false);
  }, [incident?.alert_id, incident?.case_owner, incident?.case_status]);

  if (loading) {
    return (
      <section className="panel detail-panel">
        <div className="empty-state">
          <strong>Loading selected incident...</strong>
          <span>Fetching the latest enrichment and policy detail.</span>
        </div>
      </section>
    );
  }

  if (!incident) {
    return (
      <section className="panel detail-panel">
        <div className="empty-state">
          <strong>Select an incident to inspect it.</strong>
          <span>The right-hand panel will show enrichment, actions, case context, and report preview.</span>
        </div>
      </section>
    );
  }

  const enriched = incident.enriched_alert;
  const ip = enriched.ip_enrichment;
  const hash = enriched.hash_enrichment;
  const executionTrace = incident.response.execution_trace ?? {
    configured_mode: "sync",
    effective_mode: "sync",
    queue_name: null,
    fallback_reason: null,
    queued_actions: [],
  };
  const correlationTrace = incident.response.correlation_trace ?? {
    enabled: false,
    window: null,
    outcome: "new_incident",
    incident_key: incident.incident_key,
    matched_incident_id: null,
    matched_alert_ids: [],
    related_alert_ids: incident.related_alert_ids ?? [],
    related_alert_count: incident.related_alert_count ?? 1,
    evidence: [],
    candidate_fingerprints: [],
  };
  const queuedActions = executionTrace.queued_actions ?? [];
  const reportHtmlPath = incident.report.html_path ?? incident.report_path;
  const reportArtifacts = [
    { label: "Markdown", value: incident.report.markdown_path },
    { label: "HTML", value: reportHtmlPath },
    { label: "PDF", value: incident.report.pdf_path },
  ].filter((artifact) => artifact.value);
  const summaryFacts = [
    { label: "Ticket", value: incident.ticket_id ?? "Pending" },
    { label: "Owner", value: incident.case_owner ?? "Unassigned" },
    { label: "Case", value: titleCase(incident.case_status.replace(/_/g, " ")) },
    { label: "Received", value: incident.alert.received_at ? formatDateTime(incident.alert.received_at) : "Not set" },
    { label: "Completed", value: formatDateTime(incident.completed_at) },
    { label: "Risk", value: formatRiskScore(incident.risk_score) },
    { label: "Incident key", value: incident.incident_key },
    { label: "Grouped alerts", value: `${incident.related_alert_count}` },
    { label: "Queue", value: `${incident.queued_action_count}/${incident.pending_approval_count}/${incident.running_action_count}/${incident.failed_action_count}` },
    { label: "Notes", value: `${incident.note_count}` },
  ];
  const workflowSnapshot = {
    enriched_alert: incident.enriched_alert,
    response: incident.response,
    report: incident.report,
    notes: incident.notes,
    audit_events: incident.audit_events,
  };

  return (
    <section className="panel detail-panel" data-active-tab={activeTab}>
      <div className="section-head">
        <div>
          <span className="eyebrow">Deep dive</span>
          <h2>{incident.hostname}</h2>
        </div>
        <div className="badge-group">
          <span className={`badge ${riskTone(incident.risk_level)}`}>{incident.risk_level.toUpperCase()}</span>
          <span className="badge tone-neutral">{statusLabel(incident.status)}</span>
          <span className="badge tone-sky">{formatRiskScore(incident.risk_score)}</span>
        </div>
      </div>

      <p className="detail-summary">{incident.detection_name}</p>

      <div className="detail-overview detail-overview-wide">
        {summaryFacts.map((fact) => (
          <div className="detail-overview-item" key={fact.label}>
            <span>{fact.label}</span>
            <strong>{fact.value}</strong>
          </div>
        ))}
      </div>

      <div aria-label="Incident sections" className="detail-tabs" role="tablist">
        {DETAIL_TABS.map((tab) => (
          <button
            aria-selected={activeTab === tab.id}
            className={`detail-tab ${activeTab === tab.id ? "is-active" : ""}`}
            id={`detail-tab-${tab.id}`}
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            role="tab"
            type="button"
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="detail-grid detail-grid-expanded" data-tab="case" role="tabpanel">
        <article className="soft-card">
          <strong className="card-title">Case management</strong>
          <div className="case-editor-grid">
            <label className="field">
              <span>Owner</span>
              <input value={caseOwnerDraft} onChange={(event) => setCaseOwnerDraft(event.target.value)} />
            </label>
            <label className="field">
              <span>Status</span>
              <select value={caseStatusDraft} onChange={(event) => setCaseStatusDraft(event.target.value as IncidentCaseStatus)}>
                <option value="new">New</option>
                <option value="triaged">Triaged</option>
                <option value="in_progress">In progress</option>
                <option value="monitoring">Monitoring</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </label>
          </div>
          <div className="button-row">
            <button
              className="primary-button compact-button"
              onClick={() => onUpdateCase({ case_owner: caseOwnerDraft, case_status: caseStatusDraft })}
              type="button"
            >
              Update case
            </button>
            {(incident.case_status === "resolved" || incident.case_status === "closed") && (
              <button
                className="secondary-button compact-button"
                onClick={() => onReopenIncident("Reopened from dashboard for additional analyst follow-up")}
                type="button"
              >
                Reopen case
              </button>
            )}
          </div>
          <div className="stack-sm">
            <strong className="subtle-title">Analyst notes</strong>
            <textarea
              className="note-input"
              placeholder="Capture triage context, approvals, or remediation rationale."
              rows={4}
              value={noteDraft}
              onChange={(event) => setNoteDraft(event.target.value)}
            />
            <div className="button-row">
              <button
                className="primary-button compact-button"
                disabled={noteDraft.trim().length === 0}
                onClick={() => {
                  onAddNote(noteDraft.trim());
                  setNoteDraft("");
                }}
                type="button"
              >
                Add note
              </button>
            </div>
            <div className="timeline-list">
              {incident.notes.length > 0 ? (
                incident.notes.map((note) => (
                  <div className="timeline-item" key={note.note_id}>
                    <div className="timeline-head">
                      <strong>{note.author}</strong>
                      <small>{formatDateTime(note.created_at)}</small>
                    </div>
                    <p>{note.body}</p>
                  </div>
                ))
              ) : (
                <div className="empty-mini">
                  <strong>No analyst notes yet.</strong>
                  <span>Add triage context here so the incident reads like a case, not a demo row.</span>
                </div>
              )}
            </div>
          </div>
        </article>

        <article className="soft-card">
          <strong className="card-title">Case context</strong>
          <div className="key-grid">
            <div className="key-item">
              <span>User</span>
              <strong>{incident.alert.username}</strong>
            </div>
            <div className="key-item">
              <span>Severity</span>
              <strong>{titleCase(incident.alert.severity)}</strong>
            </div>
            <div className="key-item">
              <span>Process</span>
              <strong>{incident.alert.process_name}</strong>
            </div>
            <div className="key-item">
              <span>Parent process</span>
              <strong>{incident.alert.parent_process}</strong>
            </div>
            <div className="key-item">
              <span>Destination IP</span>
              <strong>{incident.alert.destination_ip}</strong>
            </div>
            <div className="key-item">
              <span>Detection</span>
              <strong>{incident.alert.detection_name}</strong>
            </div>
          </div>
          <div className="stacked-code">
            <div className="code-block-wrap">
              <span className="code-label">File path</span>
              <div className="code-card wrap-anywhere">{incident.alert.file_path}</div>
            </div>
            <div className="code-block-wrap">
              <span className="code-label">Command line</span>
              <div className="code-card wrap-anywhere">{incident.alert.command_line}</div>
            </div>
            <div className="code-block-wrap">
              <span className="code-label">Alert ID / hash</span>
              <div className="code-card wrap-anywhere">
                {incident.alert.alert_id}
                {"\n"}
                {incident.alert.file_hash}
              </div>
            </div>
          </div>
        </article>

        <article className="soft-card">
          <strong className="card-title">Correlation and dedup</strong>
          <div className="key-grid">
            <div className="key-item">
              <span>Outcome</span>
              <strong>{titleCase(String(correlationTrace.outcome).replace(/_/g, " "))}</strong>
            </div>
            <div className="key-item">
              <span>Window</span>
              <strong>{correlationTrace.window ?? "Not configured"}</strong>
            </div>
            <div className="key-item">
              <span>Latest alert</span>
              <strong>{incident.latest_alert_id}</strong>
            </div>
            <div className="key-item">
              <span>Matched incident</span>
              <strong>{correlationTrace.matched_incident_id ?? "New incident"}</strong>
            </div>
          </div>
          <div className="stack-sm">
            <strong className="subtle-title">Related alerts</strong>
            {incident.related_alert_ids.length > 0 ? (
              <div className="timeline-list">
                {incident.related_alert_ids.map((alertId) => (
                  <div className="timeline-item" key={alertId}>
                    <div className="timeline-head">
                      <strong>{alertId}</strong>
                      <small>{alertId === incident.latest_alert_id ? "Latest" : "Grouped"}</small>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <span className="meta-empty">No related alerts recorded.</span>
            )}
          </div>
          <div className="stack-sm">
            <strong className="subtle-title">Correlation evidence</strong>
            {correlationTrace.evidence.length > 0 ? (
              <div className="timeline-list">
                {correlationTrace.evidence.map((evidence) => (
                  <div className="timeline-item" key={`${evidence.strategy}-${evidence.fingerprint}`}>
                    <div className="timeline-head">
                      <strong>{evidence.strategy}</strong>
                      <small>{evidence.fingerprint}</small>
                    </div>
                    <p>{Object.entries(evidence.values).map(([key, value]) => `${key}=${value}`).join(" | ")}</p>
                  </div>
                ))}
              </div>
            ) : (
              <span className="meta-empty">This alert created a fresh incident without prior correlation evidence.</span>
            )}
          </div>
        </article>
      </div>

      <div className="detail-grid detail-grid-expanded" data-tab="response" role="tabpanel">
        <article className="soft-card">
          <strong className="card-title">Asset and risk model</strong>
          <div className="key-grid">
            <div className="key-item">
              <span>Asset criticality</span>
              <strong>{titleCase(enriched.asset_criticality)}</strong>
            </div>
            <div className="key-item">
              <span>Risk level</span>
              <strong>{incident.risk_level.toUpperCase()}</strong>
            </div>
            <div className="key-item">
              <span>Risk total</span>
              <strong>{enriched.risk_breakdown.total?.toFixed(1) ?? incident.risk_score.toFixed(1)}</strong>
            </div>
            <div className="key-item">
              <span>Breakdown level</span>
              <strong>{present(enriched.risk_breakdown.risk_level, incident.risk_level)}</strong>
            </div>
          </div>
          <div className="risk-band">
            <span>Risk posture</span>
            <div className="signal-track">
              <span style={{ width: `${Math.min(100, incident.risk_score)}%` }} />
            </div>
            <strong>{formatDateTime(incident.completed_at)}</strong>
          </div>
          <div className="breakdown-list">
            {renderBreakdownRow("Hash", enriched.risk_breakdown.hash)}
            {renderBreakdownRow("IP", enriched.risk_breakdown.ip)}
            {renderBreakdownRow("Asset", enriched.risk_breakdown.asset)}
            {renderBreakdownRow("Severity", enriched.risk_breakdown.severity)}
            {renderBreakdownRow("MITRE", enriched.risk_breakdown.mitre)}
          </div>
          <div className="stack-sm">
            <strong className="subtle-title">CMDB asset metadata</strong>
            {renderObjectFacts(enriched.asset_info)}
          </div>
          <div className="stack-sm">
            <strong className="subtle-title">Risk reasoning</strong>
            {enriched.risk_breakdown.reasoning.length > 0 ? (
              <ul className="reasoning-list">
                {enriched.risk_breakdown.reasoning.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : (
              <span className="meta-empty">No scoring rationale returned.</span>
            )}
          </div>
        </article>

        <article className="soft-card">
          <strong className="card-title">Approval and response state</strong>
          <div className="action-list">
            {incident.action_results.map((action) => {
              const canApprove = action.requires_approval && action.approval_state === "pending" && action.correlation_id;
              const canRollback =
                Boolean(action.correlation_id) && (action.status === "queued" || action.status === "waiting_approval");
              const approvalOverdue =
                action.status === "waiting_approval" &&
                action.approval_state === "pending" &&
                isPastTimestamp(action.approval_due_at);
              const escalationDue =
                action.status === "waiting_approval" &&
                action.approval_state === "pending" &&
                isPastTimestamp(action.approval_escalates_at) &&
                !action.approval_escalated_at;
              return (
                <div className="action-item" key={`${action.action}-${action.executed_at}-${action.status}`}>
                  <div className="action-head">
                    <span className="badge tone-sky">{actionLabel(action.action)}</span>
                    <span className={`badge ${actionStatusTone(action.status)}`}>{statusLabel(action.status)}</span>
                  </div>
                  <p>{action.details}</p>
                  {action.approval_reason ? <small className="action-meta">{action.approval_reason}</small> : null}
                  {action.approval_comment ? <small className="action-meta">Comment: {action.approval_comment}</small> : null}
                  {action.approval_due_at ? (
                    <small className="action-meta">
                      Approval due: {formatDateTime(action.approval_due_at)}
                      {approvalOverdue ? " | overdue" : ""}
                    </small>
                  ) : null}
                  {action.approval_escalates_at ? (
                    <small className="action-meta">
                      Escalate at: {formatDateTime(action.approval_escalates_at)}
                      {escalationDue ? " | escalation due" : ""}
                    </small>
                  ) : null}
                  {action.escalation_targets.length > 0 ? (
                    <small className="action-meta">Escalation targets: {action.escalation_targets.join(", ")}</small>
                  ) : null}
                  {action.approval_escalated_at ? (
                    <small className="action-meta">Escalated: {formatDateTime(action.approval_escalated_at)}</small>
                  ) : null}
                  {action.rollback_requested_by || action.rollback_requested_at ? (
                    <small className="action-meta">
                      Cancelled by {action.rollback_requested_by ?? "analyst"}
                      {action.rollback_requested_at ? ` | ${formatDateTime(action.rollback_requested_at)}` : ""}
                    </small>
                  ) : null}
                  {action.attempt_count > 0 || action.correlation_id ? (
                    <small className="action-meta">
                      {action.attempt_count > 0 ? `Attempt ${action.attempt_count}` : "Async action"}
                      {action.correlation_id ? ` | ${action.correlation_id}` : ""}
                      {action.approved_by ? ` | ${action.approved_by}` : ""}
                    </small>
                  ) : null}
                  <small>{formatDateTime(action.executed_at)}</small>
                  {canApprove || canRollback ? (
                    <div className="button-row">
                      {canApprove ? (
                        <>
                          <button
                            className="primary-button compact-button"
                            onClick={() => onApproveAction(action.correlation_id!, "Approved from dashboard")}
                            type="button"
                          >
                            Approve
                          </button>
                          <button
                            className="secondary-button compact-button"
                            onClick={() => onRejectAction(action.correlation_id!, "Rejected from dashboard")}
                            type="button"
                          >
                            Reject
                          </button>
                        </>
                      ) : null}
                      {canRollback ? (
                        <button
                          className="secondary-button compact-button"
                          onClick={() => onRollbackAction(action.correlation_id!, "Cancelled from dashboard before execution")}
                          type="button"
                        >
                          Cancel queued action
                        </button>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </article>
      </div>

      <div className="detail-grid detail-grid-expanded" data-tab="intel" role="tabpanel">
        <article className="soft-card">
          <strong className="card-title">Hash intelligence</strong>
          {hash ? (
            <>
              <div className="key-grid">
                <div className="key-item">
                  <span>Reputation</span>
                  <strong>{titleCase(hash.reputation)}</strong>
                </div>
                <div className="key-item">
                  <span>Threat name</span>
                  <strong>{present(hash.threat_name, "Unlabeled")}</strong>
                </div>
                <div className="key-item">
                  <span>Meaningful name</span>
                  <strong>{present(hash.meaningful_name, "Not set")}</strong>
                </div>
                <div className="key-item">
                  <span>Source</span>
                  <strong>{hash.source}</strong>
                </div>
                <div className="key-item">
                  <span>Vendor hits</span>
                  <strong>{`${hash.malicious_vendors}/${hash.total_vendors}`}</strong>
                </div>
                <div className="key-item">
                  <span>Community score</span>
                  <strong>{hash.community_reputation ?? "Not set"}</strong>
                </div>
                <div className="key-item">
                  <span>Last analysis</span>
                  <strong>{hash.last_analysis_date ? formatDateTime(hash.last_analysis_date) : "Not set"}</strong>
                </div>
                <div className="key-item">
                  <span>Vendor split</span>
                  <strong>{`S:${hash.suspicious_vendors} H:${hash.harmless_vendors} U:${hash.undetected_vendors}`}</strong>
                </div>
              </div>
              <div className="stack-sm">
                <strong className="subtle-title">Hash / permalink</strong>
                <div className="code-card wrap-anywhere">{present(hash.hash_value, incident.alert.file_hash)}</div>
                {hash.permalink ? (
                  <a className="report-link wrap-link" href={hash.permalink} rel="noreferrer" target="_blank">
                    Open VirusTotal file object
                  </a>
                ) : null}
              </div>
              <div className="stack-sm">
                <strong className="subtle-title">Tags</strong>
                {renderTagRow(hash.tags)}
              </div>
              <div className="stack-sm">
                <strong className="subtle-title">Analysis stats</strong>
                {renderAnalysisStats(hash.analysis_stats)}
              </div>
            </>
          ) : (
            <div className="empty-mini">
              <strong>No hash enrichment returned.</strong>
              <span>The alert did not produce file reputation telemetry.</span>
            </div>
          )}
        </article>

        <article className="soft-card">
          <strong className="card-title">IP intelligence</strong>
          {ip ? (
            <>
              <div className="key-grid">
                <div className="key-item">
                  <span>Reputation</span>
                  <strong>{titleCase(ip.reputation)}</strong>
                </div>
                <div className="key-item">
                  <span>Confidence</span>
                  <strong>{`${ip.confidence_score}/100`}</strong>
                </div>
                <div className="key-item">
                  <span>C2 signal</span>
                  <strong>{ip.is_c2 ? "Flagged" : "Not flagged"}</strong>
                </div>
                <div className="key-item">
                  <span>Source</span>
                  <strong>{ip.source}</strong>
                </div>
                <div className="key-item">
                  <span>Country / ISP</span>
                  <strong>{`${ip.country ?? "Unknown"} / ${ip.isp ?? "Unknown"}`}</strong>
                </div>
                <div className="key-item">
                  <span>ASN / network</span>
                  <strong>{`${ip.asn ?? "N/A"} / ${ip.network ?? "N/A"}`}</strong>
                </div>
                <div className="key-item">
                  <span>Community score</span>
                  <strong>{ip.community_reputation ?? "Not set"}</strong>
                </div>
                <div className="key-item">
                  <span>Vendor split</span>
                  <strong>{`M:${ip.malicious_vendors} S:${ip.suspicious_vendors} H:${ip.harmless_vendors}`}</strong>
                </div>
              </div>
              <div className="stack-sm">
                <strong className="subtle-title">IP / permalink</strong>
                <div className="code-card wrap-anywhere">{ip.ip_address}</div>
                {ip.permalink ? (
                  <a className="report-link wrap-link" href={ip.permalink} rel="noreferrer" target="_blank">
                    Open VirusTotal IP object
                  </a>
                ) : null}
              </div>
              <div className="stack-sm">
                <strong className="subtle-title">Tags</strong>
                {renderTagRow(ip.tags)}
              </div>
              <div className="stack-sm">
                <strong className="subtle-title">Analysis stats</strong>
                {renderAnalysisStats(ip.analysis_stats)}
              </div>
            </>
          ) : (
            <div className="empty-mini">
              <strong>No IP enrichment returned.</strong>
              <span>The alert did not produce network reputation telemetry.</span>
            </div>
          )}
        </article>
      </div>

      <article className="soft-card" data-tab="intel" role="tabpanel">
        <strong className="card-title">MITRE ATT&amp;CK coverage</strong>
        {incident.enriched_alert.mitre_mappings.length > 0 ? (
          <div className="mitre-grid">
            {incident.enriched_alert.mitre_mappings.map((mapping) => (
              <div className="mitre-card" key={`${mapping.technique_id}-${mapping.technique_name}`}>
                <span className="badge tone-neutral">{mapping.technique_id}</span>
                <strong>{mapping.technique_name}</strong>
                <p>{mapping.tactic}</p>
                <small>{mapping.matched_pattern}</small>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-mini">
            <strong>No MITRE mapping was emitted.</strong>
            <span>This alert completed without ATT&amp;CK technique coverage metadata.</span>
          </div>
        )}
      </article>

      <div className="detail-grid detail-grid-tight" data-tab="trace" role="tabpanel">
        <article className="soft-card">
          <strong className="card-title">Execution trace</strong>
          <div className="key-grid">
            <div className="key-item">
              <span>Configured mode</span>
              <strong>{readableTraceValue(executionTrace.configured_mode)}</strong>
            </div>
            <div className="key-item">
              <span>Effective mode</span>
              <strong>{readableTraceValue(executionTrace.effective_mode)}</strong>
            </div>
            <div className="key-item">
              <span>Queue name</span>
              <strong>{present(executionTrace.queue_name)}</strong>
            </div>
            <div className="key-item">
              <span>Queued actions</span>
              <strong>{queuedActions.length}</strong>
            </div>
            <div className="key-item">
              <span>Fallback reason</span>
              <strong>{present(executionTrace.fallback_reason, "None")}</strong>
            </div>
          </div>
          {queuedActions.length > 0 ? (
            <div className="execution-queue-list">
              {queuedActions.map((request) => (
                <div className="queue-item execution-queue-item" key={request.correlation_id}>
                  <div className="action-head">
                    <span className="badge tone-sky">{actionLabel(request.action)}</span>
                    <span className={`badge ${request.requires_approval ? "tone-medium" : "tone-neutral"}`}>
                      {request.requires_approval ? "Approval gated" : present(request.queue_name)}
                    </span>
                  </div>
                  <p>{summarizeQueuedAction(request)}</p>
                  <small className="mono wrap-anywhere">{request.correlation_id}</small>
                  {request.correlation_hooks.length > 0 ? (
                    <small>
                      Hooks: {request.correlation_hooks.map((hook) => `${hook.field}=${hook.value}`).join(", ")}
                    </small>
                  ) : null}
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-mini">
              <strong>No queued actions were emitted.</strong>
              <span>This incident ran through the synchronous policy path.</span>
            </div>
          )}
        </article>

        <article className="soft-card report-preview-card">
          <div className="report-head">
            <strong className="card-title">Report preview</strong>
            {reportHtmlPath ? (
              <button
                className="secondary-button compact-button"
                disabled={openingReport}
                onClick={async () => {
                  setOpeningReport(true);
                  setReportOpenError(null);
                  try {
                    await openIncidentReport(incident.alert_id);
                  } catch (error) {
                    setReportOpenError(error instanceof Error ? error.message : "Unable to open the HTML report.");
                  } finally {
                    setOpeningReport(false);
                  }
                }}
                type="button"
              >
                Open HTML report
              </button>
            ) : null}
          </div>
          {reportOpenError ? <div className="banner banner-error">{reportOpenError}</div> : null}
          {reportArtifacts.length > 0 ? (
            <div className="artifact-list">
              {reportArtifacts.map((artifact) => (
                <div className="artifact-item" key={artifact.label}>
                  <span>{artifact.label}</span>
                  <strong className="mono artifact-value wrap-anywhere" title={artifact.value ?? undefined}>
                    {artifact.value}
                  </strong>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-mini">
              <strong>No report artifacts were generated.</strong>
              <span>Enable report generation to publish Markdown, HTML, or PDF output.</span>
            </div>
          )}
          <div className="report-preview-body report-preview-body-expanded">
            {incident.report.markdown_content ? (
              renderMarkdownPreview(incident.report.markdown_content)
            ) : (
              <div className="narrative-block">No report content available.</div>
            )}
          </div>
        </article>
      </div>

      <div className="detail-grid detail-grid-tight" data-tab="audit" role="tabpanel">
        <article className="soft-card">
          <strong className="card-title">Audit timeline</strong>
          <div className="timeline-list">
            {incident.audit_events.length > 0 ? (
              incident.audit_events.map((event) => (
                <div className="timeline-item" key={event.event_id}>
                  <div className="timeline-head">
                    <strong>{titleCase(event.category.replace(/[._]/g, " "))}</strong>
                    <small>{formatDateTime(event.created_at)}</small>
                  </div>
                  <p>{event.message}</p>
                  <small className="action-meta">{event.actor}</small>
                  {event.event_hash ? <small className="action-meta">Hash: {event.event_hash.slice(0, 16)}</small> : null}
                  {event.previous_event_hash ? (
                    <small className="action-meta">Previous: {event.previous_event_hash.slice(0, 16)}</small>
                  ) : null}
                  {Object.keys(event.payload).length > 0 ? renderObjectFacts(event.payload) : null}
                </div>
              ))
            ) : (
              <div className="empty-mini">
                <strong>No audit events yet.</strong>
                <span>Workflow and analyst actions will accumulate here.</span>
              </div>
            )}
          </div>
        </article>
        <article className="soft-card">
          <strong className="card-title">Policy reasoning</strong>
          <ul className="reasoning-list">
            {incident.policy_reasoning.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </article>
      </div>

      <div className="detail-grid detail-grid-code" data-tab="raw" role="tabpanel">
        <article className="soft-card">
          <strong className="card-title">Raw alert payload</strong>
          <pre className="raw-json">{JSON.stringify(incident.alert, null, 2)}</pre>
        </article>
        <article className="soft-card">
          <strong className="card-title">Workflow snapshot</strong>
          <pre className="raw-json">{JSON.stringify(workflowSnapshot, null, 2)}</pre>
        </article>
      </div>
    </section>
  );
}
