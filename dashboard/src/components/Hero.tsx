import { formatRelativeTime, formatRiskScore } from "../lib/format";
import type { ApiMode, IncidentRecord } from "../types";

interface HeroProps {
  apiMode: ApiMode;
  highlightedIncident: IncidentRecord | null;
  incidentCount: number;
}

export function Hero({ apiMode, highlightedIncident, incidentCount }: HeroProps) {
  return (
    <section className="hero panel">
      <div className="hero-copy">
        <div className="hero-kicker">
          <span className="dot" />
          Light-tone SOC surface
        </div>
        <h1>SOAR Command Deck</h1>
        <p>
          A bright, Vercel-ready frontend for malware triage, automated response, and executive-readable incident
          context. The interface is decoupled from the data source, so you can swap in Supabase or your API later
          without reshaping the UI.
        </p>

        <div className="hero-pills">
          <span className={`badge ${apiMode === "api" ? "tone-low" : "tone-medium"}`}>
            {apiMode === "api" ? "API linked" : "Mock mode enabled"}
          </span>
          <span className="badge tone-sky">{incidentCount} incidents indexed</span>
          <span className="badge tone-neutral">HTML + CSS + TypeScript + Node</span>
        </div>
      </div>

      <div className="hero-signal">
        <div className="signal-card">
          <div className="signal-head">
            <span>Live focus</span>
            <strong>{highlightedIncident ? formatRelativeTime(highlightedIncident.completed_at) : "Awaiting input"}</strong>
          </div>

          {highlightedIncident ? (
            <>
              <h2>{highlightedIncident.hostname}</h2>
              <p>{highlightedIncident.detection_name}</p>

              <div className="signal-stats">
                <div>
                  <span>Risk</span>
                  <strong className={`tone-text-${highlightedIncident.risk_level}`}>
                    {highlightedIncident.risk_level.toUpperCase()}
                  </strong>
                </div>
                <div>
                  <span>Score</span>
                  <strong>{formatRiskScore(highlightedIncident.risk_score)}</strong>
                </div>
                <div>
                  <span>Ticket</span>
                  <strong>{highlightedIncident.ticket_id ?? "Pending"}</strong>
                </div>
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
