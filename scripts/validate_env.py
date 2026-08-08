from __future__ import annotations

import argparse
from pathlib import Path

BASE_REQUIRED_KEYS = {
    "SOAR_ENVIRONMENT",
    "SOAR_SOURCE_PROVIDER",
    "SOAR_ACTION_PROVIDER",
    "SOAR_TICKETING_CONNECTOR",
    "SOAR_TICKETING_PROVIDER",
    "SOAR_ASSET_PROVIDER",
    "SOAR_INTEL_PROVIDER",
    "SOAR_API_CORS_ORIGINS",
    "SOAR_AUTH_TOKENS_JSON",
    "VITE_SOAR_API_BASE_URL",
}

ONE_OF_DATABASE_KEYS = {
    "SOAR_DB_TARGET",
    "SOAR_DATABASE_URL",
    "SUPABASE_DB_URL",
}

CONDITIONAL_REQUIRED_KEYS = {
    ("SOAR_TICKETING_PROVIDER", "webhook"): {"SOAR_TICKETING_WEBHOOK_URL", "SOAR_TICKETING_WEBHOOK_TOKEN"},
    ("SOAR_ASSET_PROVIDER", "http"): {"SOAR_ASSET_API_URL", "SOAR_ASSET_API_TOKEN"},
    ("SOAR_INTEL_PROVIDER", "virustotal"): {"VIRUSTOTAL_API_KEY"},
}


def parse_env_file(path: str | Path) -> dict[str, str]:
    env_path = Path(path)
    values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def validate_env_values(values: dict[str, str]) -> list[str]:
    issues: list[str] = []
    for key in sorted(BASE_REQUIRED_KEYS):
        if key not in values:
            issues.append(f"Missing required key: {key}")

    if not any(key in values for key in ONE_OF_DATABASE_KEYS):
        issues.append(
            "Missing database target. Provide at least one of: "
            + ", ".join(sorted(ONE_OF_DATABASE_KEYS))
        )

    for (selector_key, selector_value), required_keys in CONDITIONAL_REQUIRED_KEYS.items():
        if values.get(selector_key, "").strip().lower() != selector_value:
            continue
        for required_key in sorted(required_keys):
            if required_key not in values:
                issues.append(
                    f"Missing required key for {selector_key}={selector_value}: {required_key}"
                )

    return issues


def validate_env_file(path: str | Path) -> list[str]:
    return validate_env_values(parse_env_file(path))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate environment profile files used by Docker Compose and deployment workflows."
    )
    parser.add_argument("path", nargs="+", help="One or more .env-style files to validate.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    failed = False
    for raw_path in args.path:
        path = Path(raw_path)
        issues = validate_env_file(path)
        if issues:
            failed = True
            print(f"[FAIL] {path}")
            for issue in issues:
                print(f"  - {issue}")
            continue
        print(f"[PASS] {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
