import { formatDateTime, statusLabel, titleCase } from "../lib/format";
import type { IncidentRecord, IncidentSummary, RiskLevel } from "../types";

interface IncidentTableProps {
  incidents: IncidentSummary[];
  incidentDetails: Record<string, IncidentRecord>;
  loading: boolean;
  selectedAlertId: string | null;
  search: string;
  riskFilter: RiskLevel | "all";
  onSearchChange: (value: string) => void;
  onRiskFilterChange: (value: RiskLevel | "all") => void;
  onSelect: (alertId: string) => void;
}

export function IncidentTable({
  incidents,
  incidentDetails,
  loading,
  selectedAlertId,
  search,
  riskFilter,
  onSearchChange,
  onRiskFilterChange,
  onSelect,
}: IncidentTableProps) {
  function fact(label: string, value: string | undefined) {
    return (
      <span className="incident-fact" key={label}>
        <small>{label}</small>
        <strong>{value && value.trim().length > 0 ? value : "—"}</strong>
      </span>
    );
  }

  return (
    <section className="panel incidents-panel">
      <div className="section-head">
        <div>
          <span className="eyebrow">History</span>
          <h2>Incident stream</h2>
        </div>
        <span className="badge tone-neutral">{incidents.length} visible</span>
      </div>

      <div className="filter-bar">
        <label className="field inline-field">
          <span>Search</span>
          <input
            placeholder="Alert ID, host, detection, ticket"
            value={search}
            onChange={(event) => onSearchChange(event.target.value)}
          />
        </label>
        <label className="field inline-field">
          <span>Risk</span>
          <select value={riskFilter} onChange={(event) => onRiskFilterChange(event.target.value as RiskLevel | "all")}>
            <option value="all">All levels</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
      </div>

      <div className="incident-list">
        {loading ? (
          <div className="empty-state">
            <strong>Loading incidents...</strong>
            <span>The deck is refreshing the incident list.</span>
          </div>
        ) : incidents.length === 0 ? (
          <div className="empty-state">
            <strong>No incidents match the current filters.</strong>
            <span>Try a wider search or process a new alert.</span>
          </div>
        ) : (
          incidents.map((incident) => {
            const detail = incidentDetails[incident.alert_id];
            const severity = detail?.alert.severity ?? incident.severity;
            const processName = detail?.alert.process_name ?? incident.process_name;
            const destinationIp = detail?.alert.destination_ip ?? incident.destination_ip;
            const score = `${incident.risk_score.toFixed(1)} / 100`;

            return (
              <button
                className={`incident-row ${selectedAlertId === incident.alert_id ? "is-selected" : ""}`}
                key={incident.alert_id}
                onClick={() => onSelect(incident.alert_id)}
                type="button"
              >
                <div className="incident-row-top">
                  <div className="incident-primary">
                    <div className="incident-title-row">
                      <strong>{incident.hostname}</strong>
                      <span className={`badge tone-${incident.risk_level}`}>{incident.risk_level.toUpperCase()}</span>
                    </div>
                    <p>{incident.detection_name}</p>
                    <span className="mono incident-id">{incident.alert_id}</span>
                  </div>
                  <div className="incident-updated">
                    <span>Updated</span>
                    <strong>{formatDateTime(incident.completed_at)}</strong>
                  </div>
                </div>

                <div className="incident-facts">
                  {fact("Severity", severity ? titleCase(severity) : undefined)}
                  {fact("Process", processName)}
                  {fact("Destination IP", destinationIp)}
                  {fact("Status", statusLabel(incident.status))}
                  {fact("Risk Score", score)}
                  {fact("Ticket", incident.ticket_id ?? "Pending")}
                </div>
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}
