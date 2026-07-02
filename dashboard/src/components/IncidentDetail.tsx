import type { ReactNode } from "react";

import { actionLabel, formatDateTime, formatRiskScore, riskTone, statusLabel, titleCase } from "../lib/format";
import { buildIncidentReportUrl } from "../services/soarApi";
import type { IncidentRecord, QueuedActionRequest } from "../types";

interface IncidentDetailProps {
  incident: IncidentRecord | null;
  loading: boolean;
}

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
    .slice(0, 4);

  if (entries.length === 0) {
    return "No payload metadata";
  }

  return entries.map(([key, value]) => `${key}=${value}`).join(" | ");
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

export function IncidentDetail({ incident, loading }: IncidentDetailProps) {
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
          <span>The right-hand panel will show enrichment, actions, MITRE mappings, and the report preview.</span>
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
  const queuedActions = executionTrace.queued_actions ?? [];
  const reportHtmlPath = incident.report.html_path ?? incident.report_path;
  const reportUrl = reportHtmlPath ? buildIncidentReportUrl(incident.alert_id) : null;
  const reportArtifacts = [
    { label: "Markdown", value: incident.report.markdown_path },
    { label: "HTML", value: reportHtmlPath },
    { label: "PDF", value: incident.report.pdf_path },
  ].filter((artifact) => artifact.value);
  const summaryFacts = [
    { label: "Ticket", value: incident.ticket_id ?? "Pending" },
    { label: "Completed", value: formatDateTime(incident.completed_at) },
    { label: "Process", value: incident.alert.process_name },
    { label: "Asset", value: titleCase(enriched.asset_criticality) },
  ];

  return (
    <section className="panel detail-panel">
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

      <div className="detail-overview">
        {summaryFacts.map((fact) => (
          <div className="detail-overview-item" key={fact.label}>
            <span>{fact.label}</span>
            <strong>{fact.value}</strong>
          </div>
        ))}
      </div>

      <div className="detail-grid">
        <article className="soft-card">
          <strong className="card-title">Asset context</strong>
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
              <span>Parent process</span>
              <strong>{incident.alert.parent_process}</strong>
            </div>
            <div className="key-item">
              <span>Asset criticality</span>
              <strong>{titleCase(enriched.asset_criticality)}</strong>
            </div>
          </div>
          <div className="code-card">{incident.alert.command_line}</div>
        </article>

        <article className="soft-card">
          <strong className="card-title">Threat telemetry</strong>
          <div className="key-grid">
            <div className="key-item">
              <span>Hash reputation</span>
              <strong>{titleCase(hash?.reputation ?? "unknown")}</strong>
            </div>
            <div className="key-item">
              <span>Threat name</span>
              <strong>{hash?.threat_name ?? "No label"}</strong>
            </div>
            <div className="key-item">
              <span>Vendor hits</span>
              <strong>
                {hash ? `${hash.malicious_vendors}/${hash.total_vendors}` : "No data"}
              </strong>
            </div>
            <div className="key-item">
              <span>Hash intel source</span>
              <strong>{present(hash?.source, "No data")}</strong>
            </div>
            <div className="key-item">
              <span>Destination IP</span>
              <strong>{ip?.ip_address ?? incident.alert.destination_ip}</strong>
            </div>
            <div className="key-item">
              <span>Network verdict</span>
              <strong>{titleCase(ip?.reputation ?? "unknown")}</strong>
            </div>
            <div className="key-item">
              <span>IP confidence</span>
              <strong>{ip ? `${ip.confidence_score}/100` : "No data"}</strong>
            </div>
            <div className="key-item">
              <span>IP intel source</span>
              <strong>{present(ip?.source, "No data")}</strong>
            </div>
            <div className="key-item">
              <span>Country / ISP</span>
              <strong>{ip ? `${ip.country ?? "Unknown"} / ${ip.isp ?? "Unknown"}` : "No data"}</strong>
            </div>
            <div className="key-item">
              <span>C2 signal</span>
              <strong>{ip?.is_c2 ? "Flagged" : "Not flagged"}</strong>
            </div>
            <div className="key-item">
              <span>Intel sources</span>
              <strong>{[hash?.source, ip?.source].filter(Boolean).join(" + ") || "No data"}</strong>
            </div>
          </div>
          <div className="risk-band">
            <span>Risk posture</span>
            <div className="signal-track">
              <span style={{ width: `${Math.min(100, incident.risk_score)}%` }} />
            </div>
            <strong>{formatDateTime(incident.completed_at)}</strong>
          </div>
        </article>
      </div>

      <div className="detail-grid detail-grid-tight">
        <article className="soft-card">
          <strong className="card-title">Automated response</strong>
          <div className="action-list">
            {incident.action_results.map((action) => (
              <div className="action-item" key={`${action.action}-${action.executed_at}`}>
                <div className="action-head">
                  <span className="badge tone-sky">{actionLabel(action.action)}</span>
                  <span className={`badge ${action.status === "queued" ? "tone-neutral" : "tone-low"}`}>
                    {statusLabel(action.status)}
                  </span>
                </div>
                <p>{action.details}</p>
                <small>{formatDateTime(action.executed_at)}</small>
              </div>
            ))}
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

      <article className="soft-card">
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

      <div className="detail-grid detail-grid-tight">
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
                    <span className="badge tone-neutral">{present(request.queue_name)}</span>
                  </div>
                  <p>{summarizeQueuedAction(request)}</p>
                  <small className="mono">{request.correlation_id}</small>
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
        <article className="soft-card">
          <div className="report-head">
            <strong className="card-title">Report preview</strong>
            {reportUrl ? (
              <a className="report-link" href={reportUrl} rel="noreferrer" target="_blank">
                Open HTML report
              </a>
            ) : null}
          </div>
          {reportArtifacts.length > 0 ? (
            <div className="artifact-list">
              {reportArtifacts.map((artifact) => (
                <div className="artifact-item" key={artifact.label}>
                  <span>{artifact.label}</span>
                  <strong className="mono">{artifact.value}</strong>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-mini">
              <strong>No report artifacts were generated.</strong>
              <span>Enable report generation to publish Markdown, HTML, or PDF output.</span>
            </div>
          )}
          {incident.report.markdown_content ? (
            renderMarkdownPreview(incident.report.markdown_content)
          ) : (
            <div className="narrative-block">No report content available.</div>
          )}
        </article>
      </div>

      <article className="soft-card">
        <strong className="card-title">Raw alert payload</strong>
        <pre className="raw-json">{JSON.stringify(incident.alert, null, 2)}</pre>
      </article>
    </section>
  );
}
