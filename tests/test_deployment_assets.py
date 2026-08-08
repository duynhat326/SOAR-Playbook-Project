from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

from scripts.apply_postgres_migrations import discover_migrations
from scripts.validate_env import validate_env_file


def test_environment_profiles_validate():
    repo_root = Path(__file__).resolve().parent.parent
    for env_path in (
        repo_root / "config" / "environments" / "development.env",
        repo_root / "config" / "environments" / "staging.env.example",
        repo_root / "config" / "environments" / "production.env.example",
    ):
        assert validate_env_file(env_path) == []


def test_postgres_migration_baseline_exists_and_is_ordered():
    repo_root = Path(__file__).resolve().parent.parent
    migrations = discover_migrations(repo_root / "migrations" / "postgres")

    assert migrations
    assert [path.name for path in migrations] == sorted(path.name for path in migrations)
    assert "CREATE TABLE IF NOT EXISTS alerts" in migrations[0].read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS queue_jobs" in migrations[0].read_text(encoding="utf-8")


def test_docker_compose_declares_phase7_services():
    repo_root = Path(__file__).resolve().parent.parent
    compose = yaml.safe_load((repo_root / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    assert {"api", "worker", "dashboard", "postgres"} <= set(services)
    assert services["api"]["build"]["target"] == "api"
    assert services["worker"]["build"]["target"] == "worker"
    assert services["dashboard"]["build"]["dockerfile"] == "docker/Dockerfile.dashboard"
    assert services["postgres"]["profiles"] == ["postgres"]


def test_release_compose_declares_image_based_rollout_services():
    repo_root = Path(__file__).resolve().parent.parent
    compose = yaml.safe_load((repo_root / "docker-compose.release.yml").read_text(encoding="utf-8"))
    postgres_override = yaml.safe_load(
        (repo_root / "docker-compose.release.postgres.yml").read_text(encoding="utf-8")
    )

    services = compose["services"]
    override_services = postgres_override["services"]

    assert {"api", "worker", "dashboard", "migrate"} <= set(services)
    assert services["api"]["image"].startswith("ghcr.io/${SOAR_IMAGE_NAMESPACE}/soar-playbook-api:")
    assert services["worker"]["image"].startswith("ghcr.io/${SOAR_IMAGE_NAMESPACE}/soar-playbook-worker:")
    assert services["dashboard"]["image"].startswith(
        "ghcr.io/${SOAR_IMAGE_NAMESPACE}/soar-playbook-dashboard:"
    )
    assert services["migrate"]["profiles"] == ["ops"]
    assert override_services["postgres"]["profiles"] == ["postgres"]
    assert override_services["api"]["environment"]["SOAR_DATABASE_URL"].startswith(
        "postgresql://${SOAR_POSTGRES_USER:-soar}:"
    )


def test_backend_and_dashboard_dockerfiles_reference_expected_entrypoints():
    repo_root = Path(__file__).resolve().parent.parent
    backend = (repo_root / "docker" / "Dockerfile.backend").read_text(encoding="utf-8")
    dashboard = (repo_root / "docker" / "Dockerfile.dashboard").read_text(encoding="utf-8")

    assert 'uvicorn", "api.app:app"' in backend
    assert 'python", "scripts/run_remediation_worker.py"' in backend
    assert "nginx:1.27-alpine" in dashboard
    assert "VITE_SOAR_API_BASE_URL" in dashboard


def test_apply_postgres_migrations_entrypoint_help():
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "scripts/apply_postgres_migrations.py", "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Apply ordered Postgres schema migrations" in result.stdout


def test_validate_env_entrypoint_help():
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "scripts/validate_env.py", "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Validate environment profile files" in result.stdout


def test_deploy_workflow_references_remote_compose_rollout():
    repo_root = Path(__file__).resolve().parent.parent
    workflow = yaml.safe_load((repo_root / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8"))
    deploy_job = workflow["jobs"]["deploy"]
    steps = deploy_job["steps"]

    assert workflow["on"]["workflow_dispatch"]["inputs"]["environment"]["options"] == [
        "staging",
        "production",
    ]
    assert deploy_job["environment"] == "${{ inputs.environment }}"
    assert any(step.get("run") == "bash scripts/deploy_remote_compose.sh" for step in steps)
