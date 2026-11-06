import type { FormEvent } from "react";
import { titleCase } from "../lib/format";
import type { ApiMode, ReadinessState } from "../types";

interface TopbarProps {
  apiMode: ApiMode;
  incidentCount: number;
  pendingApprovals: number;
  readiness: ReadinessState | null;
  isAuthenticated: boolean;
  tokenDraft: string;
  onTokenChange: (value: string) => void;
  onAuthSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClearSession: () => void;
  onOpenIntake: () => void;
}

function ShieldMark() {
  return (
    <svg aria-hidden="true" focusable="false" height="26" viewBox="0 0 24 24" width="26">
      <path
        d="M12 2.5 4.5 5.4v5.7c0 4.6 3.1 8.8 7.5 10.4 4.4-1.6 7.5-5.8 7.5-10.4V5.4L12 2.5Z"
        fill="none"
        stroke="currentColor"
        strokeLinejoin="round"
        strokeWidth="1.6"
      />
      <path d="m8.6 12.2 2.4 2.4 4.4-4.9" fill="none" stroke="currentColor" strokeLinecap="round" strokeWidth="1.8" />
    </svg>
  );
}

export function Topbar({
  apiMode,
  incidentCount,
  pendingApprovals,
  readiness,
  isAuthenticated,
  tokenDraft,
  onTokenChange,
  onAuthSubmit,
  onClearSession,
  onOpenIntake,
}: TopbarProps) {
  const connected = apiMode === "api";
  const dependencies = readiness?.dependencies ?? [];

  return (
    <header className="topbar">
      <div className="topbar-brand">
        <span className="brand-mark">
          <ShieldMark />
        </span>
        <div>
          <h1>SOAR Command Deck</h1>
          <p>Malware triage &amp; remediation</p>
        </div>
      </div>

      <div className="topbar-status" role="status">
        <span className={`status-pill ${connected ? "is-ok" : "is-bad"}`}>
          <span className="status-dot" aria-hidden="true" />
          {connected ? "Backend connected" : "Backend unavailable"}
        </span>
        {isAuthenticated ? (
          <>
            <span className="status-pill">{incidentCount} incidents</span>
            <span className={`status-pill ${pendingApprovals > 0 ? "is-warn" : ""}`}>
              {pendingApprovals} awaiting approval
            </span>
            {dependencies.map((dependency) => (
              <span
                className={`status-pill ${dependency.status === "ready" ? "is-ok" : "is-warn"}`}
                key={dependency.name}
                title={dependency.detail}
              >
                <span className="status-dot" aria-hidden="true" />
                {titleCase(dependency.name.replace(/_/g, " "))}: {dependency.provider}
              </span>
            ))}
          </>
        ) : null}
      </div>

      <div className="topbar-actions">
        {isAuthenticated ? (
          <button className="primary-button compact-button" onClick={onOpenIntake} type="button">
            + New alert
          </button>
        ) : null}
        <details className="session-menu" open={!isAuthenticated}>
          <summary className="secondary-button compact-button">
            {isAuthenticated ? "Session active" : "Sign in"}
          </summary>
          <form className="session-form" onSubmit={onAuthSubmit}>
            <label className="field">
              <span>Bearer token</span>
              <input
                autoComplete="off"
                onChange={(event) => onTokenChange(event.target.value)}
                placeholder="Paste an operator token for this tab"
                type="password"
                value={tokenDraft}
              />
            </label>
            <div className="auth-actions">
              <button className="primary-button compact-button" type="submit">
                {isAuthenticated ? "Replace token" : "Unlock dashboard"}
              </button>
              {isAuthenticated ? (
                <button className="secondary-button compact-button" onClick={onClearSession} type="button">
                  Clear session
                </button>
              ) : null}
            </div>
            <p className="auth-copy">
              Stored only in this tab&apos;s <code>sessionStorage</code>; the proxy forwards it as your own credential.
            </p>
          </form>
        </details>
      </div>
    </header>
  );
}
