from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from env_utils import load_local_env_files
from services.remediation_queue import build_async_worker


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local async remediation worker.")
    parser.add_argument("--db-target", default=None, help="Optional SQLite path or Postgres DSN override.")
    parser.add_argument("--queue-name", default=None, help="Restrict the worker to a specific queue name.")
    parser.add_argument("--worker-id", default=None, help="Optional worker identifier.")
    return parser.parse_args()


def main() -> None:
    load_local_env_files()
    args = parse_args()
    worker = build_async_worker(
        db_target=args.db_target,
        queue_name=args.queue_name,
        worker_id=args.worker_id,
    )
    worker.run_forever()


if __name__ == "__main__":
    main()
