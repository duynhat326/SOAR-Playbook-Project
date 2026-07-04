import { formatDateTime } from "../lib/format";

interface MetricStripProps {
  totalIncidents: number;
  priorityQueue: number;
  activeQueueCount: number;
  averageRisk: number;
  ticketedIncidents: number;
  latestCompletedAt?: string | null;
}

export function MetricStrip({
  totalIncidents,
  priorityQueue,
  activeQueueCount,
  averageRisk,
  ticketedIncidents,
  latestCompletedAt,
}: MetricStripProps) {
  const cards = [
    {
      label: "Persisted Incidents",
      value: totalIncidents.toString(),
      foot: "Historical workflow executions currently indexed in the dashboard.",
      tone: "sky",
    },
    {
      label: "Remediation Queue",
      value: priorityQueue.toString(),
      foot: `${activeQueueCount} incident(s) currently need analyst or worker attention.`,
      tone: "critical",
    },
    {
      label: "Average Risk",
      value: averageRisk ? averageRisk.toFixed(1) : "0.0",
      foot: "Mean risk score across the current dataset.",
      tone: "medium",
    },
    {
      label: "Ticketed Incidents",
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
