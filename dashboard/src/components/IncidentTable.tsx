import { useEffect, useState } from "react";

import { formatDateTime, statusLabel, titleCase } from "../lib/format";
import type { IncidentCaseStatus, IncidentRecord, IncidentSummary, RiskLevel, SavedFilter } from "../types";

interface IncidentTableProps {
  incidents: IncidentSummary[];
  incidentDetails: Record<string, IncidentRecord>;
  loading: boolean;
  selectedAlertId: string | null;
  selectedRows: string[];
  search: string;
  riskFilter: RiskLevel | "all";
  caseFilter: IncidentCaseStatus | "all";
  savedFilters: SavedFilter[];
  onSearchChange: (value: string) => void;
  onRiskFilterChange: (value: RiskLevel | "all") => void;
  onCaseFilterChange: (value: IncidentCaseStatus | "all") => void;
  onToggleRow: (alertId: string) => void;
  onToggleAll: (checked: boolean) => void;
  onSelect: (alertId: string) => void;
  onBulkUpdate: (payload: { case_status?: string; case_owner?: string; comment?: string }) => void;
  onApplySavedFilter: (filter: SavedFilter) => void;
  onSaveCurrentFilter: () => void;
}

export function IncidentTable({
  incidents,
  incidentDetails,
  loading,
  selectedAlertId,
  selectedRows,
  search,
  riskFilter,
  caseFilter,
  savedFilters,
  onSearchChange,
  onRiskFilterChange,
  onCaseFilterChange,
  onToggleRow,
  onToggleAll,
  onSelect,
  onBulkUpdate,
  onApplySavedFilter,
  onSaveCurrentFilter,
}: IncidentTableProps) {
  const [bulkOwner, setBulkOwner] = useState("SOC Team");
  const [bulkStatus, setBulkStatus] = useState<IncidentCaseStatus>("triaged");

  useEffect(() => {
    if (selectedRows.length === 0) {
      setBulkOwner("SOC Team");
      setBulkStatus("triaged");
    }
  }, [selectedRows]);

  function fact(label: string, value: string | undefined) {
    return (
      <span className="incident-fact" key={label}>
        <small>{label}</small>
        <strong>{value && value.trim().length > 0 ? value : "-"}</strong>
      </span>
    );
  }

  const allVisibleSelected = incidents.length > 0 && incidents.every((incident) => selectedRows.includes(incident.alert_id));

  return (
    <section className="panel incidents-panel">
      <div className="section-head">
        <div>
          <span className="eyebrow">History</span>
          <h2>Incident stream</h2>
        </div>
        <span className="badge tone-neutral">{incidents.length} visible</span>
      </div>

      <div className="filter-bar filter-bar-extended">
        <label className="field inline-field">
          <span>Search</span>
          <input
            placeholder="Alert ID, host, detection, ticket, owner"
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
        <label className="field inline-field">
          <span>Case</span>
          <select value={caseFilter} onChange={(event) => onCaseFilterChange(event.target.value as IncidentCaseStatus | "all")}>
            <option value="all">All cases</option>
            <option value="new">New</option>
            <option value="triaged">Triaged</option>
            <option value="in_progress">In progress</option>
            <option value="monitoring">Monitoring</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
        </label>
      </div>

      <div className="saved-filter-row">
        {savedFilters.slice(0, 6).map((filter) => (
          <button className="filter-chip" key={filter.id} onClick={() => onApplySavedFilter(filter)} type="button">
            {filter.name}
          </button>
        ))}
        <button className="filter-chip filter-chip-ghost" onClick={onSaveCurrentFilter} type="button">
          Save current filter
        </button>
      </div>

      <div className="bulk-toolbar">
        <label className="select-all-toggle">
          <input checked={allVisibleSelected} onChange={(event) => onToggleAll(event.target.checked)} type="checkbox" />
          <span>Select all visible</span>
        </label>
        <strong>{selectedRows.length} selected</strong>
        <label className="field inline-field compact-field">
          <span>Owner</span>
          <input value={bulkOwner} onChange={(event) => setBulkOwner(event.target.value)} />
        </label>
        <label className="field inline-field compact-field">
          <span>Status</span>
          <select value={bulkStatus} onChange={(event) => setBulkStatus(event.target.value as IncidentCaseStatus)}>
            <option value="triaged">Triaged</option>
            <option value="in_progress">In progress</option>
            <option value="monitoring">Monitoring</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>
        </label>
        <button
          className="primary-button compact-button"
          disabled={selectedRows.length === 0}
          onClick={() => onBulkUpdate({ case_owner: bulkOwner, case_status: bulkStatus })}
          type="button"
        >
          Apply bulk triage
        </button>
      </div>

      <div className="incident-list compact-incident-list">
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
            const hashIntel = detail?.enriched_alert.hash_enrichment;
            const score = `${incident.risk_score.toFixed(1)} / 100`;
            const vendorState = hashIntel ? `${hashIntel.malicious_vendors}/${hashIntel.total_vendors}` : "Pending";

            return (
              <div
                className={`incident-row compact-incident-row ${selectedAlertId === incident.alert_id ? "is-selected" : ""}`}
                key={incident.alert_id}
              >
                <div className="incident-selection">
                  <input
                    checked={selectedRows.includes(incident.alert_id)}
                    onChange={() => onToggleRow(incident.alert_id)}
                    type="checkbox"
                  />
                </div>
                <button className="incident-row-button" onClick={() => onSelect(incident.alert_id)} type="button">
                  <div className="incident-row-top">
                    <div className="incident-primary">
                      <div className="incident-title-row">
                        <strong>{incident.hostname}</strong>
                        <span className={`badge tone-${incident.risk_level}`}>{incident.risk_level.toUpperCase()}</span>
                        <span className="badge tone-neutral">{titleCase(incident.case_status.replace(/_/g, " "))}</span>
                      </div>
                      <p>{incident.detection_name}</p>
                      <span className="mono incident-id">{incident.alert_id}</span>
                    </div>
                    <div className="incident-updated">
                      <span>Updated</span>
                      <strong>{formatDateTime(incident.completed_at)}</strong>
                    </div>
                  </div>

                  <div className="incident-facts compact-facts">
                    {fact("Owner", incident.case_owner ?? "Unassigned")}
                    {fact("Severity", severity ? titleCase(severity) : undefined)}
                    {fact("Process", processName)}
                    {fact("IP", destinationIp)}
                    {fact("Status", statusLabel(incident.status))}
                    {fact("Grouped", `${incident.related_alert_count}`)}
                    {fact(
                      "Queue",
                      `Q${incident.queued_action_count} A${incident.pending_approval_count} R${incident.running_action_count} F${incident.failed_action_count}`,
                    )}
                    {fact("VT", vendorState)}
                    {fact("Score", score)}
                    {fact("Notes", `${incident.note_count}`)}
                    {fact("Ticket", incident.ticket_id ?? "Pending")}
                  </div>
                </button>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
