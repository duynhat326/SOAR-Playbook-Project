import { formatDateTime } from "../lib/format";
import type { RiskLevel } from "../types";

interface MetricStripProps {
  totalIncidents: number;
  pendingApprovals: number;
  activeQueueCount: number;
  averageRisk: number;
  ticketedIncidents: number;
  latestCompletedAt?: string | null;
  riskCounts: Record<RiskLevel, number>;
}

const RISK_ORDER: RiskLevel[] = ["critical", "high", "medium", "low"];

export function MetricStrip({
  totalIncidents,
  pendingApprovals,
  activeQueueCount,
  averageRisk,
  ticketedIncidents,
  latestCompletedAt,
  riskCounts,
}: MetricStripProps) {
  const cards = [
    { label: "Incidents", value: totalIncidents.toString(), foot: latestCompletedAt ? `Latest ${formatDateTime(latestCompletedAt)}` : "None processed yet", tone: "sky" },
    { label: "Awaiting approval", value: pendingApprovals.toString(), foot: "Actions blocked on an analyst", tone: pendingApprovals > 0 ? "critical" : "neutral" },
    { label: "Needs attention", value: activeQueueCount.toString(), foot: "Queued, failed or approval-blocked", tone: activeQueueCount > 0 ? "medium" : "neutral" },
    { label: "Average risk", value: averageRisk ? averageRisk.toFixed(1) : "0.0", foot: "Mean score, 0-100", tone: "medium" },
    { label: "Ticketed", value: ticketedIncidents.toString(), foot: `${totalIncidents - ticketedIncidents} without a ticket`, tone: "low" },
  ];

  return (
    <section aria-label="Key metrics" className="metric-grid">
      {cards.map((card) => (
        <article className={`metric-card tone-border-${card.tone}`} key={card.label}>
          <div className="metric-label">{card.label}</div>
          <strong className="metric-value">{card.value}</strong>
          <p>{card.foot}</p>
        </article>
      ))}

      <article className="metric-card metric-card-wide">
        <div className="metric-label">Risk distribution</div>
        <div
          aria-label={RISK_ORDER.map((level) => `${riskCounts[level]} ${level}`).join(", ")}
          className="risk-bar"
          role="img"
        >
          {RISK_ORDER.map((level) =>
            riskCounts[level] > 0 ? (
              <span className={`risk-seg tone-bg-${level}`} key={level} style={{ flexGrow: riskCounts[level] }} />
            ) : null,
          )}
          {totalIncidents === 0 ? <span className="risk-seg risk-seg-empty" style={{ flexGrow: 1 }} /> : null}
        </div>
        <ul className="risk-legend">
          {RISK_ORDER.map((level) => (
            <li key={level}>
              <span className={`legend-swatch tone-bg-${level}`} aria-hidden="true" />
              {level} <strong>{riskCounts[level]}</strong>
            </li>
          ))}
        </ul>
      </article>
    </section>
  );
}
