import type { RiskLevel } from "../types";

const DATE_TIME_FORMATTER = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});

export function formatDateTime(value?: string | null): string {
  if (!value) {
    return "No data";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return DATE_TIME_FORMATTER.format(date);
}

export function formatRelativeTime(value?: string | null): string {
  if (!value) {
    return "No recent activity";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  const delta = Math.max(0, Date.now() - date.getTime());
  const minutes = Math.floor(delta / 60000);

  if (minutes < 1) {
    return "Moments ago";
  }

  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function formatRiskScore(score: number): string {
  return `${score.toFixed(1)} / 100`;
}

export function titleCase(value: string): string {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function riskTone(level: RiskLevel): string {
  return `tone-${level}`;
}

export function actionLabel(action: string): string {
  return titleCase(action.replace(/_/g, " "));
}

export function statusLabel(status: string): string {
  return titleCase(status.replace(/_/g, " "));
}
