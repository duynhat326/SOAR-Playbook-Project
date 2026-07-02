import { formatDateTime } from "../lib/format";

interface MetricStripProps {
  totalIncidents: number;
  priorityQueue: number;
  averageRisk: number;
  ticketedIncidents: number;
  latestCompletedAt?: string | null;
}

export function MetricStrip({
  totalIncidents,
  priorityQueue,
  averageRisk,
  ticketedIncidents,
  latestCompletedAt,
}: MetricStripProps) {
  const cards = [
    {
      label: "Persisted incidents",
      value: totalIncidents.toString(),
      foot: "Historical alert executions tracked in the deck.",
      tone: "sky",
    },
    {
      label: "Priority queue",
      value: priorityQueue.toString(),
      foot: "High and critical cases that should stay visible.",
      tone: "critical",
    },
    {
      label: "Average risk",
      value: averageRisk ? averageRisk.toFixed(1) : "0.0",
      foot: "Mean risk score across the current dataset.",
      tone: "medium",
    },
    {
      label: "Ticketed incidents",
      value: ticketedIncidents.toString(),
      foot: latestCompletedAt ? `Latest: ${formatDateTime(latestCompletedAt)}` : "No incidents processed yet.",
      tone: "low",
    },
  ];

  return (
    <section className="metric-grid">
      {cards.map((card) => (
        <article className="metric-card panel" key={card.label}>
          <span className={`metric-ribbon tone-${card.tone}`} />
          <div className="metric-label">{card.label}</div>
          <strong className="metric-value">{card.value}</strong>
          <p>{card.foot}</p>
        </article>
      ))}
    </section>
  );
}
