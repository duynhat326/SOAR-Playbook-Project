from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

from observability import observability
from alert_generator.generator import generate_alert
from engine.policy_engine import PolicyEngine
from engine.policy_loader import DEFAULT_POLICY_CONFIG
from services.remediation_queue import (
    AsyncRemediationWorker,
    RemediationQueueSettings,
    RepositoryQueuePublisher,
)
from services.workflow_service import SoarWorkflowService
from storage.sqlite_repository import SQLiteIncidentRepository


def _counter_value(name: str, **labels: str) -> float:
    snapshot = observability.snapshot()
    for counter in snapshot["metrics"]["counters"]:
        if counter["name"] != name:
            continue
        if all(counter["labels"].get(key) == str(value) for key, value in labels.items()):
            return float(counter["value"])
    return 0.0


def _write_queued_policy(tmp_path):
    config_data = yaml.safe_load(yaml.safe_dump(DEFAULT_POLICY_CONFIG, sort_keys=False))
    config_data["execution"]["mode"] = "queued"
    config_path = tmp_path / "response_rules.yaml"
    config_path.write_text(yaml.safe_dump(config_data, sort_keys=False), encoding="utf-8")
    return config_path


def test_async_worker_executes_queued_remediation_and_updates_incident(tmp_path):
    repository = SQLiteIncidentRepository(tmp_path / "soar.db")
    policy_path = _write_queued_policy(tmp_path)
    publisher = RepositoryQueuePublisher(
        repository,
        settings=RemediationQueueSettings(max_attempts=2),
    )
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=policy_path,
            queue_publisher=publisher,
        ),
    )
    worker = AsyncRemediationWorker(repository, worker_id="pytest-worker")

    alert = generate_alert(scenario="malicious_hash", seed=4242)
    result = service.process_alert(alert, generate_report=False, export_pdf=False)

    queued_result = next(action for action in result.response.action_results if action.action == "isolate_host")
    assert queued_result.status == "queued"

    assert worker.run_once() is True

    incident = repository.get_incident_by_alert_id(alert.alert_id)
    assert incident is not None
    isolate_result = next(action for action in incident["action_results"] if action["action"] == "isolate_host")
    assert isolate_result["status"] == "succeeded"
    assert isolate_result["attempt_count"] == 1
    assert incident["status"] == "completed"
    assert _counter_value("queue.completed_total", worker_id="pytest-worker", action="isolate_host") == 1.0


def test_async_worker_dead_letters_failed_jobs_when_attempts_are_exhausted(tmp_path, monkeypatch):
    repository = SQLiteIncidentRepository(tmp_path / "soar.db")
    policy_path = _write_queued_policy(tmp_path)
    publisher = RepositoryQueuePublisher(
        repository,
        settings=RemediationQueueSettings(max_attempts=1),
    )
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=policy_path,
            queue_publisher=publisher,
        ),
    )
    worker = AsyncRemediationWorker(repository, worker_id="pytest-worker")

    monkeypatch.setattr(
        "services.remediation_queue.execute_queued_action",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("forced worker failure")),
    )

    alert = generate_alert(scenario="malicious_hash", seed=5252)
    service.process_alert(alert, generate_report=False, export_pdf=False)

    assert worker.run_once() is True

    incident = repository.get_incident_by_alert_id(alert.alert_id)
    assert incident is not None
    isolate_result = next(action for action in incident["action_results"] if action["action"] == "isolate_host")
    assert isolate_result["status"] == "failed"
    assert isolate_result["attempt_count"] == 1
    assert incident["status"] == "attention"
    assert _counter_value("queue.dead_lettered_total", worker_id="pytest-worker", action="isolate_host") == 1.0


def test_async_worker_records_retry_metrics_before_dead_letter(tmp_path, monkeypatch):
    repository = SQLiteIncidentRepository(tmp_path / "soar.db")
    policy_path = _write_queued_policy(tmp_path)
    publisher = RepositoryQueuePublisher(
        repository,
        settings=RemediationQueueSettings(max_attempts=2),
    )
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=policy_path,
            queue_publisher=publisher,
        ),
    )
    worker = AsyncRemediationWorker(
        repository,
        worker_id="pytest-worker",
        settings=RemediationQueueSettings(
            max_attempts=2,
            base_retry_delay_seconds=0.0,
            max_retry_delay_seconds=0.0,
        ),
    )

    monkeypatch.setattr(
        "services.remediation_queue.execute_queued_action",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("forced worker failure")),
    )

    alert = generate_alert(scenario="malicious_hash", seed=5353)
    service.process_alert(alert, generate_report=False, export_pdf=False)

    assert worker.run_once() is True
    assert worker.run_once() is True

    incident = repository.get_incident_by_alert_id(alert.alert_id)
    assert incident is not None
    isolate_result = next(action for action in incident["action_results"] if action["action"] == "isolate_host")
    assert isolate_result["status"] == "failed"
    assert isolate_result["attempt_count"] == 2
    assert _counter_value("queue.retry_scheduled_total", worker_id="pytest-worker", action="isolate_host") == 1.0
    assert _counter_value("queue.dead_lettered_total", worker_id="pytest-worker", action="isolate_host") == 1.0


def test_async_worker_waits_for_approval_until_analyst_approves(tmp_path, monkeypatch):
    monkeypatch.setenv("SOAR_APPROVAL_REQUIRED_ACTIONS", "isolate_host")
    repository = SQLiteIncidentRepository(tmp_path / "soar.db")
    policy_path = _write_queued_policy(tmp_path)
    publisher = RepositoryQueuePublisher(
        repository,
        settings=RemediationQueueSettings(max_attempts=2),
    )
    service = SoarWorkflowService(
        verbose=False,
        repository=repository,
        policy_engine=PolicyEngine(
            verbose=False,
            policy_config_path=policy_path,
            queue_publisher=publisher,
        ),
    )
    worker = AsyncRemediationWorker(repository, worker_id="pytest-worker")

    alert = generate_alert(scenario="malicious_hash", seed=6262)
    result = service.process_alert(alert, generate_report=False, export_pdf=False)

    queued_result = next(action for action in result.response.action_results if action.action == "isolate_host")
    assert queued_result.status == "waiting_approval"
    assert worker.run_once() is False

    incident = repository.approve_action_job(
        alert.alert_id,
        queued_result.correlation_id,
        actor="pytest-analyst",
        comment="Approval granted for containment",
    )
    assert incident is not None

    approved_action = next(action for action in incident["action_results"] if action["action"] == "isolate_host")
    assert approved_action["approval_state"] == "approved"
    assert approved_action["status"] == "queued"

    assert worker.run_once() is True

    final_incident = repository.get_incident_by_alert_id(alert.alert_id)
    assert final_incident is not None
    final_action = next(action for action in final_incident["action_results"] if action["action"] == "isolate_host")
    assert final_action["status"] == "succeeded"
    assert final_action["approved_by"] == "pytest-analyst"


def test_run_remediation_worker_entrypoint_loads_from_repo_root():
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "scripts/run_remediation_worker.py", "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Run the local async remediation worker." in result.stdout
