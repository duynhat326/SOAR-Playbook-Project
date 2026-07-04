import { formatRelativeTime, formatRiskScore, statusLabel } from "../lib/format";
import type { ApiMode, IncidentRecord } from "../types";

interface HeroProps {
  apiMode: ApiMode;
  highlightedIncident: IncidentRecord | null;
  incidentCount: number;
}

export function Hero({ apiMode, highlightedIncident, incidentCount }: HeroProps) {
  const hasActiveRemediation =
    highlightedIncident?.action_results.some(
      (action) => action.status === "queued" || action.status === "running" || action.status === "waiting_approval",
    ) ?? false;
  const intelSource =
    [highlightedIncident?.enriched_alert.hash_enrichment?.source, highlightedIncident?.enriched_alert.ip_enrichment?.source]
      .filter(Boolean)
      .join(" + ") || "Awaiting enrichment";
  const remediationState = highlightedIncident
    ? hasActiveRemediation
      ? "Queue active"
      : statusLabel(highlightedIncident.status)
    : "Awaiting input";

  return (
    <section className="hero panel">
      <div className="hero-copy">
        <div className="hero-kicker">
          <span className="dot" />
          Malware Triage and Remediation
        </div>
        <h1>SOAR Command Deck</h1>
        <p>
          Live incident operations across enrichment, policy evaluation, queued remediation, and report generation.
          The deck now reflects the persisted backend dataset instead of client-side simulation.
        </p>

        <div className="hero-pills">
          <span className={`badge ${apiMode === "api" ? "tone-low" : "tone-critical"}`}>
            {apiMode === "api" ? "Backend connected" : "Backend unavailable"}
          </span>
          <span className="badge tone-sky">{incidentCount} incidents indexed</span>
          <span className="badge tone-neutral">VirusTotal + CMDB + Policy engine</span>
        </div>
      </div>

      <div className="hero-signal">
        <div className="signal-card">
          <div className="signal-head">
            <span>Live Focus</span>
            <strong>{highlightedIncident ? formatRelativeTime(highlightedIncident.completed_at) : "Awaiting input"}</strong>
          </div>

          {highlightedIncident ? (
            <>
              <div className="signal-incident">
                <h2>{highlightedIncident.hostname}</h2>
                <p className="signal-detection">{highlightedIncident.detection_name}</p>
              </div>

              <div className="signal-grid">
                <div className="signal-chip">
                  <span>Risk</span>
                  <strong className={`tone-text-${highlightedIncident.risk_level}`}>
                    {highlightedIncident.risk_level.toUpperCase()}
                  </strong>
                </div>
                <div className="signal-chip">
                  <span>Score</span>
                  <strong>{formatRiskScore(highlightedIncident.risk_score)}</strong>
                </div>
                <div className="signal-chip">
                  <span>Remediation</span>
                  <strong>{remediationState}</strong>
                </div>
                <div className="signal-chip">
                  <span>Ticket</span>
                  <strong>{highlightedIncident.ticket_id ?? "Pending"}</strong>
                </div>
                <div className="signal-chip">
                  <span>Vendor hits</span>
                  <strong>
                    {highlightedIncident.enriched_alert.hash_enrichment
                      ? `${highlightedIncident.enriched_alert.hash_enrichment.malicious_vendors}/${highlightedIncident.enriched_alert.hash_enrichment.total_vendors}`
                      : "Pending"}
                  </strong>
                </div>
                <div className="signal-chip signal-chip-wide">
                  <span>Intel source</span>
                  <strong title={intelSource}>{intelSource}</strong>
                </div>
              </div>

              <div className="signal-footnote">
                <span>Selected case</span>
                <strong>{statusLabel(highlightedIncident.status)}</strong>
              </div>

              <div className="signal-track">
                <span style={{ width: `${Math.min(100, highlightedIncident.risk_score)}%` }} />
              </div>
            </>
          ) : (
            <div className="empty-mini">
              <strong>No incident selected</strong>
              <span>Process a scenario or paste a JSON alert to populate the deck.</span>
            </div>
          )}
        </div>

        <div className="orb orb-a" />
        <div className="orb orb-b" />
        <div className="orb orb-c" />
      </div>
    </section>
  );
}
