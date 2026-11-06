import { startTransition, useDeferredValue, useEffect, useState, type FormEvent } from "react";
import { IncidentDetail } from "./components/IncidentDetail";
import { IncidentTable } from "./components/IncidentTable";
import { IntakePanel } from "./components/IntakePanel";
import { MetricStrip } from "./components/MetricStrip";
import { Topbar } from "./components/Topbar";
import { formatDateTime, formatRelativeTime, titleCase } from "./lib/format";
import {
  addIncidentNote,
  approveAction,
  bulkUpdateIncidents,
  clearDashboardAuthToken,
  getDashboardAuthToken,
  getFallbackDashboardBootstrap,
  getIncident,
  getReadiness,
  listIncidents,
  listSavedFilters,
  loadDashboardBootstrap,
  processAlert,
  reopenIncident,
  rejectAction,
  rollbackAction,
  saveFilter,
  setDashboardAuthToken,
  updateIncidentCase,
} from "./services/soarApi";
import type {
  ActionExecutionStatus,
  ApiMode,
  DashboardBootstrap,
  IncidentCaseStatus,
  IncidentRecord,
  IncidentSummary,
  ProcessAlertInput,
  ReadinessState,
  RiskLevel,
  SavedFilter,
} from "./types";

interface BannerState {
  tone: "success" | "error";
  message: string;
}

interface RefreshOptions {
  silent?: boolean;
}


function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected dashboard error.";
}

function isLiveActionStatus(status: ActionExecutionStatus): boolean {
  return status === "queued" || status === "waiting_approval" || status === "running";
}

function compareIncidents(left: IncidentSummary, right: IncidentSummary): number {
  const approvalDelta = right.pending_approval_count - left.pending_approval_count;
  if (approvalDelta !== 0) {
    return approvalDelta;
  }

  const activeDelta = right.active_action_count - left.active_action_count;
  if (activeDelta !== 0) {
    return activeDelta;
  }

  const failedDelta = right.failed_action_count - left.failed_action_count;
  if (failedDelta !== 0) {
    return failedDelta;
  }

  const riskDelta = right.risk_score - left.risk_score;
  if (riskDelta !== 0) {
    return riskDelta;
  }

  return right.completed_at.localeCompare(left.completed_at);
}

function sortIncidents(items: IncidentSummary[]): IncidentSummary[] {
  return [...items].sort(compareIncidents);
}

function summarizeActionCounts(incident: IncidentRecord) {
  const queued_action_count = incident.action_results.filter((action) => action.status === "queued").length;
  const pending_approval_count = incident.action_results.filter((action) => action.status === "waiting_approval").length;
  const running_action_count = incident.action_results.filter((action) => action.status === "running").length;
  const failed_action_count = incident.action_results.filter((action) => action.status === "failed").length;
  const succeeded_action_count = incident.action_results.filter((action) => action.status === "succeeded").length;
  return {
    queued_action_count,
    pending_approval_count,
    running_action_count,
    failed_action_count,
    succeeded_action_count,
    active_action_count: queued_action_count + pending_approval_count + running_action_count,
  };
}

function toIncidentSummary(incident: IncidentRecord): IncidentSummary {
  const actionCounts = summarizeActionCounts(incident);
  return {
    id: incident.id,
    alert_id: incident.alert_id,
    incident_key: incident.incident_key,
    latest_alert_id: incident.latest_alert_id,
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
    case_status: incident.case_status,
    case_owner: incident.case_owner,
    queued_action_count: incident.queued_action_count ?? actionCounts.queued_action_count,
    pending_approval_count: incident.pending_approval_count ?? actionCounts.pending_approval_count,
    running_action_count: incident.running_action_count ?? actionCounts.running_action_count,
    failed_action_count: incident.failed_action_count ?? actionCounts.failed_action_count,
    succeeded_action_count: incident.succeeded_action_count ?? actionCounts.succeeded_action_count,
    active_action_count: incident.active_action_count ?? actionCounts.active_action_count,
    note_count: incident.note_count ?? incident.notes.length,
    related_alert_count: incident.related_alert_count ?? incident.related_alert_ids.length ?? 1,
  };
}

function upsertIncidentSummary(current: IncidentSummary[], incoming: IncidentSummary): IncidentSummary[] {
  const next = current.filter((incident) => incident.alert_id !== incoming.alert_id);
  next.unshift(incoming);
  return sortIncidents(next);
}

function currentFilterSnapshot(
  search: string,
  riskFilter: RiskLevel | "all",
  caseFilter: IncidentCaseStatus | "all",
): Record<string, unknown> {
  return {
    search,
    risk_level: riskFilter,
    case_status: caseFilter,
  };
}

export default function App() {
  const [apiMode, setApiMode] = useState<ApiMode>("offline");
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
  const [caseFilter, setCaseFilter] = useState<IncidentCaseStatus | "all">("all");
  const [selectedRows, setSelectedRows] = useState<string[]>([]);
  const [banner, setBanner] = useState<BannerState | null>(null);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>([]);
  const [readiness, setReadiness] = useState<ReadinessState | null>(null);
  const [sessionToken, setSessionToken] = useState(() => getDashboardAuthToken());
  const [tokenDraft, setTokenDraft] = useState(() => getDashboardAuthToken());
  const [intakeOpen, setIntakeOpen] = useState(false);

  useEffect(() => {
    if (!intakeOpen) {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIntakeOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [intakeOpen]);

  const deferredSearch = useDeferredValue(search);
  const isAuthenticated = sessionToken.trim().length > 0;

  function resetDashboardState() {
    setApiMode("offline");
    setBootstrap(getFallbackDashboardBootstrap());
    setIncidents([]);
    setIncidentDetails({});
    setSelectedAlertId(null);
    setSelectedIncident(null);
    setListLoading(false);
    setDetailLoading(false);
    setProcessing(false);
    setSelectedRows([]);
    setSavedFilters([]);
    setReadiness(null);
  }

  function handleAuthSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const nextToken = tokenDraft.trim();
    if (nextToken.length === 0) {
      setBanner({ tone: "error", message: "Paste a bearer token before unlocking the dashboard." });
      return;
    }

    resetDashboardState();
    setListLoading(true);
    setSessionToken(setDashboardAuthToken(nextToken));
    setBanner({ tone: "success", message: "Dashboard session token updated for this browser tab." });
  }

  function handleClearSession() {
    clearDashboardAuthToken();
    setSessionToken("");
    setTokenDraft("");
    resetDashboardState();
    setBanner({ tone: "success", message: "Dashboard session cleared." });
  }

  async function refreshReadiness() {
    try {
      const result = await getReadiness();
      startTransition(() => {
        setApiMode(result.mode);
        setReadiness(result.readiness);
      });
    } catch (error) {
      startTransition(() => {
        setBanner({ tone: "error", message: errorMessage(error) });
      });
    }
  }

  async function refreshSavedFilters() {
    try {
      const result = await listSavedFilters();
      startTransition(() => {
        setApiMode(result.mode);
        setSavedFilters(result.filters);
      });
    } catch (error) {
      startTransition(() => {
        setBanner({ tone: "error", message: errorMessage(error) });
      });
    }
  }

  async function refreshIncidents(
    preferredAlertId?: string | null,
    preferredIncident?: IncidentRecord | null,
    options?: RefreshOptions,
  ) {
    if (!options?.silent) {
      setListLoading(true);
    }

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
        setSelectedRows((current) => current.filter((alertId) => sortedIncidents.some((incident) => incident.alert_id === alertId)));
        if (!options?.silent) {
          setListLoading(false);
        }
      });
    } catch (error) {
      startTransition(() => {
        setApiMode("offline");
        if (!options?.silent) {
          setListLoading(false);
        }
        setBanner({ tone: "error", message: errorMessage(error) });
      });
    }
  }

  async function refreshSelectedIncident(alertId: string, options?: RefreshOptions) {
    if (!options?.silent) {
      setDetailLoading(true);
    }

    try {
      const result = await getIncident(alertId);
      const incident = result.incident;

      startTransition(() => {
        setApiMode(result.mode);
        setSelectedIncident(incident);
        if (incident) {
          setIncidents((current) => upsertIncidentSummary(current, toIncidentSummary(incident)));
          setIncidentDetails((current) => ({
            ...current,
            [incident.alert_id]: incident,
          }));
        }
        if (!options?.silent) {
          setDetailLoading(false);
        }
      });
    } catch (error) {
      startTransition(() => {
        setApiMode("offline");
        if (!options?.silent) {
          setDetailLoading(false);
        }
        setBanner({ tone: "error", message: errorMessage(error) });
      });
    }
  }

  useEffect(() => {
    if (!isAuthenticated) {
      resetDashboardState();
      return;
    }

    let cancelled = false;

    async function loadInitialState() {
      try {
        const bootstrapResult = await loadDashboardBootstrap();
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setApiMode(bootstrapResult.mode);
          setBootstrap(bootstrapResult.bootstrap);
        });
      } catch (error) {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setApiMode("offline");
          setListLoading(false);
          setBanner({ tone: "error", message: errorMessage(error) });
        });
        return;
      }

      await Promise.all([refreshIncidents(), refreshReadiness(), refreshSavedFilters()]);
    }

    setListLoading(true);
    void loadInitialState();

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, sessionToken]);

  useEffect(() => {
    if (!isAuthenticated || !selectedAlertId) {
      setSelectedIncident(null);
      return;
    }

    void refreshSelectedIncident(selectedAlertId);
  }, [isAuthenticated, selectedAlertId]);

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

      await Promise.all([
        refreshIncidents(result.incident.alert_id, result.incident, { silent: true }),
        refreshReadiness(),
      ]);
    } catch (error) {
      startTransition(() => {
        setApiMode("offline");
        setBanner({ tone: "error", message: errorMessage(error) });
      });
      throw error;
    } finally {
      setProcessing(false);
    }
  }

  async function handleUpdateCase(payload: { case_status?: string; case_owner?: string; comment?: string }) {
    if (!selectedAlertId) {
      return;
    }
    try {
      const result = await updateIncidentCase(selectedAlertId, payload);
      startTransition(() => {
        setApiMode(result.mode);
        setSelectedIncident(result.incident);
        setIncidentDetails((current) => ({
          ...current,
          [result.incident.alert_id]: result.incident,
        }));
        setIncidents((current) => upsertIncidentSummary(current, toIncidentSummary(result.incident)));
        setBanner({ tone: "success", message: `Updated case ${result.incident.alert_id}.` });
      });
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  async function handleAddNote(body: string) {
    if (!selectedAlertId) {
      return;
    }
    try {
      await addIncidentNote(selectedAlertId, { body });
      await refreshSelectedIncident(selectedAlertId, { silent: true });
      startTransition(() => {
        setBanner({ tone: "success", message: `Added note to ${selectedAlertId}.` });
      });
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  async function handleApproveAction(correlationId: string, comment?: string) {
    if (!selectedAlertId) {
      return;
    }
    try {
      const result = await approveAction(selectedAlertId, correlationId, { comment });
      startTransition(() => {
        setApiMode(result.mode);
        setSelectedIncident(result.incident);
        setIncidentDetails((current) => ({
          ...current,
          [result.incident.alert_id]: result.incident,
        }));
        setIncidents((current) => upsertIncidentSummary(current, toIncidentSummary(result.incident)));
        setBanner({ tone: "success", message: `Approved action ${correlationId}.` });
      });
      await refreshReadiness();
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  async function handleRejectAction(correlationId: string, comment?: string) {
    if (!selectedAlertId) {
      return;
    }
    try {
      const result = await rejectAction(selectedAlertId, correlationId, { comment });
      startTransition(() => {
        setApiMode(result.mode);
        setSelectedIncident(result.incident);
        setIncidentDetails((current) => ({
          ...current,
          [result.incident.alert_id]: result.incident,
        }));
        setIncidents((current) => upsertIncidentSummary(current, toIncidentSummary(result.incident)));
        setBanner({ tone: "success", message: `Rejected action ${correlationId}.` });
      });
      await refreshReadiness();
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  async function handleRollbackAction(correlationId: string, comment?: string) {
    if (!selectedAlertId) {
      return;
    }
    try {
      const result = await rollbackAction(selectedAlertId, correlationId, { comment });
      startTransition(() => {
        setApiMode(result.mode);
        setSelectedIncident(result.incident);
        setIncidentDetails((current) => ({
          ...current,
          [result.incident.alert_id]: result.incident,
        }));
        setIncidents((current) => upsertIncidentSummary(current, toIncidentSummary(result.incident)));
        setBanner({ tone: "success", message: `Cancelled queued action ${correlationId}.` });
      });
      await refreshReadiness();
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  async function handleReopenIncident(comment?: string) {
    if (!selectedAlertId) {
      return;
    }
    try {
      const result = await reopenIncident(selectedAlertId, { comment });
      startTransition(() => {
        setApiMode(result.mode);
        setSelectedIncident(result.incident);
        setIncidentDetails((current) => ({
          ...current,
          [result.incident.alert_id]: result.incident,
        }));
        setIncidents((current) => upsertIncidentSummary(current, toIncidentSummary(result.incident)));
        setBanner({ tone: "success", message: `Reopened incident ${result.incident.alert_id}.` });
      });
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  async function handleBulkUpdate(payload: { case_status?: string; case_owner?: string; comment?: string }) {
    if (selectedRows.length === 0) {
      return;
    }
    try {
      const result = await bulkUpdateIncidents({
        alert_ids: selectedRows,
        case_status: payload.case_status,
        case_owner: payload.case_owner,
        comment: payload.comment,
      });
      startTransition(() => {
        setApiMode(result.mode);
        setIncidentDetails((current) => {
          const next = { ...current };
          result.incidents.forEach((incident) => {
            next[incident.alert_id] = incident;
          });
          return next;
        });
        setIncidents((current) =>
          sortIncidents(
            result.incidents.reduce(
              (next, incident) => upsertIncidentSummary(next, toIncidentSummary(incident)),
              current,
            ),
          ),
        );
        if (selectedAlertId) {
          const refreshedSelected = result.incidents.find((incident) => incident.alert_id === selectedAlertId);
          if (refreshedSelected) {
            setSelectedIncident(refreshedSelected);
          }
        }
        setBanner({ tone: "success", message: `Bulk updated ${result.incidents.length} incident(s).` });
      });
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  async function handleSaveCurrentFilter() {
    const name = window.prompt("Saved filter name", `filter-${Date.now()}`);
    if (!name) {
      return;
    }
    try {
      const result = await saveFilter(name, currentFilterSnapshot(search, riskFilter, caseFilter));
      startTransition(() => {
        setApiMode(result.mode);
        setSavedFilters((current) => [result.filter, ...current.filter((item) => item.id !== result.filter.id)]);
        setBanner({ tone: "success", message: `Saved filter '${result.filter.name}'.` });
      });
    } catch (error) {
      startTransition(() => setBanner({ tone: "error", message: errorMessage(error) }));
    }
  }

  function applySavedFilter(filter: SavedFilter) {
    const nextSearch = typeof filter.filters.search === "string" ? filter.filters.search : "";
    const nextRisk = filter.filters.risk_level;
    const nextCase = filter.filters.case_status;
    startTransition(() => {
      setSearch(nextSearch);
      setRiskFilter(nextRisk === "critical" || nextRisk === "high" || nextRisk === "medium" || nextRisk === "low" ? nextRisk : "all");
      setCaseFilter(
        nextCase === "new" ||
          nextCase === "triaged" ||
          nextCase === "in_progress" ||
          nextCase === "monitoring" ||
          nextCase === "resolved" ||
          nextCase === "closed"
          ? nextCase
          : "all",
      );
    });
  }

  const filteredIncidents = incidents.filter((incident) => {
    const matchesRisk = riskFilter === "all" || incident.risk_level === riskFilter;
    const matchesCase = caseFilter === "all" || incident.case_status === caseFilter;
    const detail = incidentDetails[incident.alert_id];
    const haystack = [
      incident.alert_id,
      incident.hostname,
      incident.detection_name,
      incident.ticket_id ?? "",
      incident.case_owner ?? "",
      detail?.alert.process_name ?? incident.process_name ?? "",
      detail?.alert.destination_ip ?? incident.destination_ip ?? "",
      detail?.alert.severity ?? incident.severity ?? "",
    ]
      .join(" ")
      .toLowerCase();
    const matchesSearch = haystack.includes(deferredSearch.trim().toLowerCase());
    return matchesRisk && matchesCase && matchesSearch;
  });

  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

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
          setApiMode("offline");
          setBanner({ tone: "error", message: errorMessage(error) });
        });
      }
    }

    void hydrateHistoryRows();

    return () => {
      cancelled = true;
    };
  }, [filteredIncidents, incidentDetails, isAuthenticated]);

  const hasLiveRemediation = incidents.some(
    (incident) =>
      incident.active_action_count > 0 ||
      incident.pending_approval_count > 0 ||
      incident.status === "remediating" ||
      incident.status === "pending_approval",
  );
  const selectedHasLiveActions =
    selectedIncident?.action_results.some((action) => isLiveActionStatus(action.status)) ?? false;

  useEffect(() => {
    if (!isAuthenticated || (!hasLiveRemediation && !selectedHasLiveActions)) {
      return;
    }

    let cancelled = false;

    async function pollLiveState() {
      try {
        const [listResult, detailResult, readinessResult] = await Promise.all([
          listIncidents(),
          selectedAlertId ? getIncident(selectedAlertId) : Promise.resolve({ mode: apiMode, incident: null }),
          getReadiness(),
        ]);
        if (cancelled) {
          return;
        }

        startTransition(() => {
          setApiMode(listResult.mode);
          setReadiness(readinessResult.readiness);
          const nextIncidents =
            detailResult.incident !== null
              ? upsertIncidentSummary(listResult.incidents, toIncidentSummary(detailResult.incident))
              : sortIncidents(listResult.incidents);
          setIncidents(nextIncidents);

          if (detailResult.incident) {
            setSelectedIncident(detailResult.incident);
            setIncidentDetails((current) => ({
              ...current,
              [detailResult.incident!.alert_id]: detailResult.incident!,
            }));
          }
        });
      } catch (error) {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setApiMode("offline");
          setBanner({ tone: "error", message: errorMessage(error) });
        });
      }
    }

    const intervalId = window.setInterval(() => {
      void pollLiveState();
    }, 2500);

    void pollLiveState();

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [apiMode, hasLiveRemediation, isAuthenticated, selectedAlertId, selectedHasLiveActions]);

  const priorityQueue = sortIncidents(
    incidents.filter(
      (incident) =>
        incident.pending_approval_count > 0 ||
        incident.active_action_count > 0 ||
        incident.failed_action_count > 0 ||
        incident.status === "attention",
    ),
  );
  const activeQueueCount = priorityQueue.length;
  const averageRisk = incidents.length
    ? incidents.reduce((sum, incident) => sum + incident.risk_score, 0) / incidents.length
    : 0;
  const ticketedIncidents = incidents.filter((incident) => Boolean(incident.ticket_id)).length;
  const latestCompletedAt = incidents[0]?.completed_at ?? null;
  const pendingApprovals = incidents.reduce((sum, incident) => sum + incident.pending_approval_count, 0);
  const riskCounts = incidents.reduce(
    (counts, incident) => {
      counts[incident.risk_level] = (counts[incident.risk_level] ?? 0) + 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0 } as Record<RiskLevel, number>,
  );

  const queuePanel = (
    <section className="panel queue-panel">
      <div className="section-head">
        <div>
          <span className="eyebrow">Priority queue</span>
          <h2>Needs attention</h2>
        </div>
        <span className="badge tone-neutral">{activeQueueCount} live</span>
      </div>

      {priorityQueue.length === 0 ? (
        <div className="empty-mini">
          <strong>Nothing needs attention</strong>
          <span>Incidents with approvals, active or failed remediation appear here.</span>
        </div>
      ) : (
        <div className="queue-list">
          {priorityQueue.slice(0, 5).map((incident) => (
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
              <small>
                {incident.pending_approval_count > 0
                  ? `${incident.pending_approval_count} action(s) waiting approval`
                  : incident.active_action_count > 0
                    ? `${incident.active_action_count} active remediation step(s)`
                    : incident.failed_action_count > 0
                      ? `${incident.failed_action_count} failed remediation step(s)`
                      : formatRelativeTime(incident.completed_at)}
              </small>
            </button>
          ))}
        </div>
      )}
    </section>
  );

  return (
    <div className="shell">
      <Topbar
        apiMode={apiMode}
        incidentCount={incidents.length}
        isAuthenticated={isAuthenticated}
        onAuthSubmit={handleAuthSubmit}
        onClearSession={handleClearSession}
        onOpenIntake={() => setIntakeOpen(true)}
        onTokenChange={setTokenDraft}
        pendingApprovals={pendingApprovals}
        readiness={readiness}
        tokenDraft={tokenDraft}
      />

      <main className="app-shell">
        {banner ? (
          <div
            className={`banner ${banner.tone === "error" ? "banner-error" : "banner-success"}`}
            role={banner.tone === "error" ? "alert" : "status"}
          >
            <span>{banner.message}</span>
            <button aria-label="Dismiss message" className="banner-close" onClick={() => setBanner(null)} type="button">
              &times;
            </button>
          </div>
        ) : null}

        {!isAuthenticated ? (
          <section className="panel locked-panel">
            <span className="eyebrow">Access</span>
            <h2>Sign in to load incidents</h2>
            <p>
              Open the <strong>Sign in</strong> menu at the top right and paste an operator bearer token. It stays in this
              browser tab only.
            </p>
          </section>
        ) : (
          <>
            <MetricStrip
              activeQueueCount={activeQueueCount}
              averageRisk={averageRisk}
              latestCompletedAt={latestCompletedAt}
              pendingApprovals={pendingApprovals}
              riskCounts={riskCounts}
              ticketedIncidents={ticketedIncidents}
              totalIncidents={incidents.length}
            />

            {queuePanel}

            <section className="workbench">
              <div className="workbench-list">
                <IncidentTable
                  incidents={filteredIncidents}
                  incidentDetails={incidentDetails}
                  loading={listLoading}
                  selectedAlertId={selectedAlertId}
                  selectedRows={selectedRows}
                  search={search}
                  riskFilter={riskFilter}
                  caseFilter={caseFilter}
                  savedFilters={savedFilters}
                  onSearchChange={(value) => startTransition(() => setSearch(value))}
                  onRiskFilterChange={(value) => setRiskFilter(value)}
                  onCaseFilterChange={(value) => setCaseFilter(value)}
                  onToggleRow={(alertId) =>
                    setSelectedRows((current) =>
                      current.includes(alertId) ? current.filter((item) => item !== alertId) : [...current, alertId],
                    )
                  }
                  onToggleAll={(checked) =>
                    setSelectedRows(checked ? filteredIncidents.map((incident) => incident.alert_id) : [])
                  }
                  onSelect={setSelectedAlertId}
                  onBulkUpdate={handleBulkUpdate}
                  onApplySavedFilter={applySavedFilter}
                  onSaveCurrentFilter={handleSaveCurrentFilter}
                />
              </div>
              <div className="workbench-detail">
                <IncidentDetail
                  incident={selectedIncident}
                  loading={detailLoading}
                  onUpdateCase={handleUpdateCase}
                  onAddNote={handleAddNote}
                  onApproveAction={handleApproveAction}
                  onRejectAction={handleRejectAction}
                  onRollbackAction={handleRollbackAction}
                  onReopenIncident={handleReopenIncident}
                />
              </div>
            </section>

            {intakeOpen ? (
              <div className="drawer-backdrop" onClick={() => setIntakeOpen(false)}>
                <aside
                  aria-label="Process an alert"
                  aria-modal="true"
                  className="drawer"
                  onClick={(event) => event.stopPropagation()}
                  role="dialog"
                >
                  <button
                    aria-label="Close intake panel"
                    className="drawer-close secondary-button compact-button"
                    onClick={() => setIntakeOpen(false)}
                    type="button"
                  >
                    Close
                  </button>
                  <IntakePanel
                    apiMode={apiMode}
                    bootstrap={bootstrap}
                    processing={processing}
                    onProcess={async (input) => {
                      await handleProcess(input);
                      setIntakeOpen(false);
                    }}
                  />
                </aside>
              </div>
            ) : null}
          </>
        )}
      </main>
    </div>
  );
}
