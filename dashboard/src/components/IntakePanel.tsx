import { useEffect, useState, type FormEvent } from "react";
import type { ApiMode, DashboardBootstrap, IntakeMode, ProcessAlertInput, ScenarioKey } from "../types";

interface IntakePanelProps {
  apiMode: ApiMode;
  bootstrap: DashboardBootstrap;
  processing: boolean;
  onProcess: (input: ProcessAlertInput) => Promise<void>;
}

function looksRedacted(value: unknown): boolean {
  const candidate = String(value ?? "").trim();
  return candidate === "[redacted]" || candidate === "[redacted-path]";
}

function isZeroHash(value: unknown): boolean {
  const candidate = String(value ?? "").trim();
  return (candidate.length === 32 || candidate.length === 40 || candidate.length === 64) && /^0+$/.test(candidate);
}

export function IntakePanel({ apiMode, bootstrap, processing, onProcess }: IntakePanelProps) {
  const [mode, setMode] = useState<IntakeMode>("scenario");
  const [scenario, setScenario] = useState<ScenarioKey>(bootstrap.default_scenario);
  const [sampleId, setSampleId] = useState(bootstrap.default_sample_id ?? bootstrap.sample_options[0]?.value ?? "");
  const [jsonDraft, setJsonDraft] = useState(bootstrap.default_json);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setScenario((current) =>
      bootstrap.scenario_options.some((option) => option.value === current) ? current : bootstrap.default_scenario,
    );
    setSampleId((current) =>
      bootstrap.sample_options.some((option) => option.value === current)
        ? current
        : bootstrap.default_sample_id ?? bootstrap.sample_options[0]?.value ?? "",
    );
    setJsonDraft((current) => (current.trim().length > 0 ? current : bootstrap.default_json));
  }, [bootstrap]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    try {
      if (mode === "json") {
        const parsed = JSON.parse(jsonDraft);
        if (
          looksRedacted(parsed?.username) ||
          looksRedacted(parsed?.command_line) ||
          looksRedacted(parsed?.file_path) ||
          isZeroHash(parsed?.file_hash)
        ) {
          throw new Error(
            "This JSON looks sanitized from the dashboard/API. Paste the original raw alert with the real hash, path, command line, and username.",
          );
        }
        await onProcess({ mode, rawJson: jsonDraft });
        return;
      }

      if (mode === "sample") {
        await onProcess({ mode, sampleId });
        return;
      }

      await onProcess({ mode, scenario });
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : "Unable to process the alert payload.");
    }
  }

  const selectedScenario = bootstrap.scenario_options.find((option) => option.value === scenario);
  const selectedSample = bootstrap.sample_options.find((option) => option.value === sampleId);

  return (
    <section className="panel intake-panel">
      <div className="section-head">
        <div>
          <span className="eyebrow">Alert intake</span>
          <h2>Launch a workflow</h2>
        </div>
        <span className={`badge ${apiMode === "api" ? "tone-low" : "tone-neutral"}`}>
          {apiMode === "api" ? "Connected endpoint" : "Local simulation"}
        </span>
      </div>

      <form className="intake-form" onSubmit={handleSubmit}>
        <div className="segmented-control" role="tablist" aria-label="Alert source">
          {[
            { value: "scenario", label: "Scenario" },
            { value: "sample", label: "Sample" },
            { value: "json", label: "JSON" },
          ].map((item) => (
            <button
              key={item.value}
              className={mode === item.value ? "is-active" : ""}
              onClick={() => setMode(item.value as IntakeMode)}
              type="button"
            >
              {item.label}
            </button>
          ))}
        </div>

        {mode === "scenario" && (
          <div className="stack-sm">
            <label className="field">
              <span>Scenario preset</span>
              <select value={scenario} onChange={(event) => setScenario(event.target.value as ScenarioKey)}>
                {bootstrap.scenario_options.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="soft-card">
              <strong>{selectedScenario?.label}</strong>
              <p>{selectedScenario?.description}</p>
            </div>
          </div>
        )}

        {mode === "sample" && (
          <div className="stack-sm">
            <label className="field">
              <span>Sample payload</span>
              <select value={sampleId} onChange={(event) => setSampleId(event.target.value)}>
                {bootstrap.sample_options.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="soft-card">
              <strong>{selectedSample?.label}</strong>
              <p>{selectedSample?.description}</p>
            </div>
          </div>
        )}

        {mode === "json" && (
          <label className="field">
            <span>Custom JSON</span>
            <textarea
              rows={11}
              value={jsonDraft}
              onChange={(event) => setJsonDraft(event.target.value)}
              spellCheck={false}
            />
          </label>
        )}

        <div className="intake-note">
          <strong>{apiMode === "api" ? "Backend mode" : "Frontend mock mode"}</strong>
          <span>
            {apiMode === "api"
              ? "Requests are sent to the configured SOAR API with browser-bound session credentials."
              : "No API is required right now. Demo incidents stay in memory for the current session only."}
          </span>
        </div>

        {error ? <div className="banner banner-error">{error}</div> : null}

        <button className="primary-button" disabled={processing} type="submit">
          {processing ? "Processing alert..." : "Process alert"}
        </button>
      </form>
    </section>
  );
}
