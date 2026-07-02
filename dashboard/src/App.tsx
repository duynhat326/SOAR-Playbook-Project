import { startTransition, useDeferredValue, useEffect, useState } from "react";
import { Hero } from "./components/Hero";
import { IncidentDetail } from "./components/IncidentDetail";
import { IncidentTable } from "./components/IncidentTable";
import { IntakePanel } from "./components/IntakePanel";
import { MetricStrip } from "./components/MetricStrip";
import { formatDateTime, formatRelativeTime } from "./lib/format";
import {
  getFallbackDashboardBootstrap,
  getIncident,
  listIncidents,
  loadDashboardBootstrap,
  processAlert,
} from "./services/soarApi";
import type {
  ApiMode,
  DashboardBootstrap,
  IncidentRecord,
  IncidentSummary,
  ProcessAlertInput,
  RiskLevel,
} from "./types";

interface BannerState {
  tone: "success" | "error";
  message: string;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected dashboard error.";
}

function sortIncidents(items: IncidentSummary[]): IncidentSummary[] {
  return [...items].sort((left, right) => right.completed_at.localeCompare(left.completed_at));
}

function toIncidentSummary(incident: IncidentRecord): IncidentSummary {
  return {
    id: incident.id,
    alert_id: incident.alert_id,
    hostname: incident.hostname,
    detection_name: incident.detection_name,
    risk_score: incident.risk_score,
    risk_level: incident.risk_level,
    severity: incident.alert.severity,
    process_name: incident.alert.process_name,
    destination_ip: incident.alert.destination_ip,
    ticket_id: incident.ticket_id,
    status: incident.status,
    completed_at: incident.completed_at,
    report_path: incident.report_path,
  };
}

function upsertIncidentSummary(current: IncidentSummary[], incoming: IncidentSummary): IncidentSummary[] {
  const next = current.filter((incident) => incident.alert_id !== incoming.alert_id);
  next.unshift(incoming);
  return sortIncidents(next);
}

export default function App() {
  const [apiMode, setApiMode] = useState<ApiMode>("mock");
  const [bootstrap, setBootstrap] = useState<DashboardBootstrap>(getFallbackDashboardBootstrap());
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [incidentDetails, setIncidentDetails] = useState<Record<string, IncidentRecord>>({});
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<IncidentRecord | null>(null);
  const [listLoading, setListLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskLevel | "all">("all");
  const [banner, setBanner] = useState<BannerState | null>(null);

  const deferredSearch = useDeferredValue(search);

  async function refreshIncidents(preferredAlertId?: string | null, preferredIncident?: IncidentRecord | null) {
    setListLoading(true);
    try {
      const result = await listIncidents();
      const sortedIncidents = preferredIncident
        ? upsertIncidentSummary(result.incidents, toIncidentSummary(preferredIncident))
        : sortIncidents(result.incidents);

      startTransition(() => {
        setApiMode(result.mode);
        setIncidents(sortedIncidents);
        const nextSelected =
          preferredAlertId && sortedIncidents.some((incident) => incident.alert_id === preferredAlertId)
            ? preferredAlertId
            : sortedIncidents[0]?.alert_id ?? null;
        setSelectedAlertId(nextSelected);
        setListLoading(false);
      });
    } catch (error) {
      startTransition(() => {
        setListLoading(false);
        setBanner({ tone: "error", message: errorMessage(error) });
      });
    }
  }

  useEffect(() => {
    async function loadBootstrap() {
      try {
        const result = await loadDashboardBootstrap();
        startTransition(() => {
          setApiMode(result.mode);
          setBootstrap(result.bootstrap);
        });
      } catch (error) {
        startTransition(() => {
          setBanner({ tone: "error", message: errorMessage(error) });
        });
      }
    }

    void loadBootstrap();
    void refreshIncidents();
  }, []);

  useEffect(() => {
    async function loadSelectedIncident() {
      if (!selectedAlertId) {
        setSelectedIncident(null);
        return;
      }

      setDetailLoading(true);
      try {
        const result = await getIncident(selectedAlertId);

        startTransition(() => {
          setApiMode(result.mode);
          setSelectedIncident(result.incident);
          if (result.incident) {
            const incident = result.incident;
            setIncidentDetails((current) => ({
              ...current,
              [incident.alert_id]: incident,
            }));
          }
          setDetailLoading(false);
        });
      } catch (error) {
        startTransition(() => {
          setDetailLoading(false);
          setBanner({ tone: "error", message: errorMessage(error) });
        });
      }
    }

    void loadSelectedIncident();
  }, [selectedAlertId]);

  async function handleProcess(input: ProcessAlertInput) {
    setProcessing(true);
    try {
      const result = await processAlert(input, bootstrap);

      startTransition(() => {
        setApiMode(result.mode);
        setSelectedAlertId(result.incident.alert_id);
        setSelectedIncident(result.incident);
        setIncidents((current) => upsertIncidentSummary(current, toIncidentSummary(result.incident)));
        setIncidentDetails((current) => ({
          ...current,
          [result.incident.alert_id]: result.incident,
        }));
        setBanner({
          tone: "success",
          message: `Processed ${result.incident.alert_id} on ${formatDateTime(result.incident.completed_at)}.`,
        });
      });

      await refreshIncidents(result.incident.alert_id, result.incident);
    } catch (error) {
      startTransition(() => {
        setBanner({ tone: "error", message: errorMessage(error) });
      });
      throw error;
    } finally {
      setProcessing(false);
    }
  }

  const filteredIncidents = incidents.filter((incident) => {
    const matchesRisk = riskFilter === "all" || incident.risk_level === riskFilter;
    const detail = incidentDetails[incident.alert_id];
    const haystack = [
      incident.alert_id,
      incident.hostname,
      incident.detection_name,
      incident.ticket_id ?? "",
      detail?.alert.process_name ?? incident.process_name ?? "",
      detail?.alert.destination_ip ?? incident.destination_ip ?? "",
      detail?.alert.severity ?? incident.severity ?? "",
    ]
      .join(" ")
      .toLowerCase();
    const matchesSearch = haystack.includes(deferredSearch.trim().toLowerCase());
    return matchesRisk && matchesSearch;
  });

  useEffect(() => {
    const incidentsToHydrate = filteredIncidents
      .filter((incident) => !incidentDetails[incident.alert_id])
      .map((incident) => incident.alert_id);

    if (incidentsToHydrate.length === 0) {
      return;
    }

    let cancelled = false;

    async function hydrateHistoryRows() {
      try {
        const resolved = await Promise.all(incidentsToHydrate.map(async (alertId) => getIncident(alertId)));
        if (cancelled) {
          return;
        }

        startTransition(() => {
          setIncidentDetails((current) => {
            const next = { ...current };
            resolved.forEach(({ incident }) => {
              if (incident) {
                next[incident.alert_id] = incident;
              }
            });
            return next;
          });
        });
      } catch (error) {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setBanner({ tone: "error", message: errorMessage(error) });
        });
      }
    }

    void hydrateHistoryRows();

    return () => {
      cancelled = true;
    };
  }, [filteredIncidents, incidentDetails]);

  const priorityQueue = incidents.filter((incident) => incident.risk_level === "critical" || incident.risk_level === "high");
  const averageRisk = incidents.length
    ? incidents.reduce((sum, incident) => sum + incident.risk_score, 0) / incidents.length
    : 0;
  const ticketedIncidents = incidents.filter((incident) => Boolean(incident.ticket_id)).length;
  const latestCompletedAt = incidents[0]?.completed_at ?? null;

  return (
    <div className="shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <div className="ambient ambient-three" />

      <main className="app-shell">
        <Hero apiMode={apiMode} highlightedIncident={selectedIncident} incidentCount={incidents.length} />

        {banner ? (
          <div className={`banner ${banner.tone === "error" ? "banner-error" : "banner-success"}`}>
            {banner.message}
          </div>
        ) : null}

        <section className="operations-grid">
          <IntakePanel apiMode={apiMode} bootstrap={bootstrap} processing={processing} onProcess={handleProcess} />

          <div className="operations-stack">
            <MetricStrip
              totalIncidents={incidents.length}
              priorityQueue={priorityQueue.length}
              averageRisk={averageRisk}
              ticketedIncidents={ticketedIncidents}
              latestCompletedAt={latestCompletedAt}
            />

            <section className="panel queue-panel">
              <div className="section-head">
                <div>
                  <span className="eyebrow">Priority queue</span>
                  <h2>Watchlist</h2>
                </div>
                <span className="badge tone-neutral">{priorityQueue.length} active</span>
              </div>

              {priorityQueue.length === 0 ? (
                <div className="empty-mini">
                  <strong>No high-priority incidents</strong>
                  <span>The queue will populate when you process higher-risk alerts.</span>
                </div>
              ) : (
                <div className="queue-list">
                  {priorityQueue.slice(0, 4).map((incident) => (
                    <button
                      className={`queue-item ${incident.alert_id === selectedAlertId ? "is-selected" : ""}`}
                      key={incident.alert_id}
                      onClick={() => setSelectedAlertId(incident.alert_id)}
                      type="button"
                    >
                      <div>
                        <span className={`badge tone-${incident.risk_level}`}>{incident.risk_level.toUpperCase()}</span>
                        <strong>{incident.hostname}</strong>
                      </div>
                      <p>{incident.detection_name}</p>
                      <small>{formatRelativeTime(incident.completed_at)}</small>
                    </button>
                  ))}
                </div>
              )}
            </section>
          </div>
        </section>

        <section className="workbench-grid">
          <IncidentTable
            incidents={filteredIncidents}
            incidentDetails={incidentDetails}
            loading={listLoading}
            selectedAlertId={selectedAlertId}
            search={search}
            riskFilter={riskFilter}
            onSearchChange={(value) => startTransition(() => setSearch(value))}
            onRiskFilterChange={(value) => setRiskFilter(value)}
            onSelect={setSelectedAlertId}
          />
          <IncidentDetail incident={selectedIncident} loading={detailLoading} />
        </section>
      </main>
    </div>
  );
}
