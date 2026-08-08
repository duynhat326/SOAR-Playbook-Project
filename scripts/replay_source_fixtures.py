from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from integrations.source_replay import run_source_fixture_suite


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay sanitized source payload fixtures through normalization, policy, and correlation.",
    )
    parser.add_argument(
        "fixture",
        nargs="+",
        help="Path(s) to source replay fixture YAML files.",
    )
    parser.add_argument(
        "--policy",
        default=str(PROJECT_ROOT / "policies" / "response_rules.yaml"),
        help="Path to the policy YAML file to evaluate.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first failing fixture.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    any_failed = False
    for fixture_path in args.fixture:
        results = run_source_fixture_suite(
            fixture_path,
            policy_config_path=args.policy,
            fail_fast=args.fail_fast,
        )
        print(f"Fixture suite: {fixture_path}")
        for result in results:
            status = "PASS" if result.passed else "FAIL"
            print(f"  [{status}] {result.fixture_id}")
            for failure in result.failures:
                print(f"    - {failure}")
            if not result.passed:
                any_failed = True
                if args.fail_fast:
                    return 1
    return 1 if any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
