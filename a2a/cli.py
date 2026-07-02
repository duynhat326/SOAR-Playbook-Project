from __future__ import annotations

import argparse
import json

from a2a.schemas import (
    AgentHeartbeatRequest,
    AgentRegistrationRequest,
    ArtifactCreateRequest,
    MessageCreateRequest,
    TaskClaimRequest,
    TaskCompleteRequest,
    TaskCreateRequest,
    WorkspaceCreateRequest,
)
from a2a.service import A2AService
from security import resolve_cli_principal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local A2A collaboration bus for Codex, Claude, Gemini, and other agents."
    )
    parser.add_argument("--db", default=None, help="Override SQLite bus path.")
    parser.add_argument("--token", default=None, help="Bearer token or SOAR_AUTH_TOKEN fallback.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    workspace_parser = subparsers.add_parser("ensure-workspace")
    workspace_parser.add_argument("--workspace", required=True)

    register_parser = subparsers.add_parser("register-agent")
    register_parser.add_argument("--workspace", required=True)
    register_parser.add_argument("--agent-id")
    register_parser.add_argument("--platform", required=True)
    register_parser.add_argument("--role", default="worker")
    register_parser.add_argument("--status", default="online")
    register_parser.add_argument("--capability", action="append", default=[])
    register_parser.add_argument("--metadata", default="{}")

    heartbeat_parser = subparsers.add_parser("heartbeat-agent")
    heartbeat_parser.add_argument("--agent-id", required=True)
    heartbeat_parser.add_argument("--status", default="online")

    list_agents_parser = subparsers.add_parser("list-agents")
    list_agents_parser.add_argument("--workspace", required=True)

    create_task_parser = subparsers.add_parser("create-task")
    create_task_parser.add_argument("--workspace", required=True)
    create_task_parser.add_argument("--title", required=True)
    create_task_parser.add_argument("--description", default="")
    create_task_parser.add_argument("--requested-by", required=True)
    create_task_parser.add_argument("--assigned-to")
    create_task_parser.add_argument("--priority", default="normal")
    create_task_parser.add_argument("--label", action="append", default=[])

    list_tasks_parser = subparsers.add_parser("list-tasks")
    list_tasks_parser.add_argument("--workspace", required=True)
    list_tasks_parser.add_argument("--status")

    claim_task_parser = subparsers.add_parser("claim-task")
    claim_task_parser.add_argument("--task-id", required=True)
    claim_task_parser.add_argument("--agent-id", required=True)

    complete_task_parser = subparsers.add_parser("complete-task")
    complete_task_parser.add_argument("--task-id", required=True)
    complete_task_parser.add_argument("--agent-id", required=True)
    complete_task_parser.add_argument("--summary")

    message_parser = subparsers.add_parser("send-message")
    message_parser.add_argument("--workspace", required=True)
    message_parser.add_argument("--sender-agent", required=True)
    message_parser.add_argument("--recipient-agent")
    message_parser.add_argument("--task-id")
    message_parser.add_argument("--kind", default="note")
    message_parser.add_argument("--content", required=True)
    message_parser.add_argument("--metadata", default="{}")

    poll_parser = subparsers.add_parser("poll-messages")
    poll_parser.add_argument("--workspace", required=True)
    poll_parser.add_argument("--agent-id", required=True)
    poll_parser.add_argument("--limit", type=int, default=20)
    poll_parser.add_argument("--after")

    artifact_parser = subparsers.add_parser("publish-artifact")
    artifact_parser.add_argument("--workspace", required=True)
    artifact_parser.add_argument("--author-agent", required=True)
    artifact_parser.add_argument("--task-id")
    artifact_parser.add_argument("--message-id")
    artifact_parser.add_argument("--kind", default="file")
    artifact_parser.add_argument("--uri", required=True)
    artifact_parser.add_argument("--summary", default="")

    timeline_parser = subparsers.add_parser("timeline")
    timeline_parser.add_argument("--workspace", required=True)
    timeline_parser.add_argument("--limit", type=int, default=50)

    return parser


def emit(payload: object) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=True))


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    service = A2AService(args.db)
    principal = resolve_cli_principal(args.token)

    if args.command == "ensure-workspace":
        emit(
            service.ensure_workspace(
                WorkspaceCreateRequest(workspace=args.workspace),
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "register-agent":
        emit(
            service.register_agent(
                AgentRegistrationRequest(
                    workspace=args.workspace,
                    agent_id=args.agent_id,
                    platform=args.platform,
                    role=args.role,
                    status=args.status,
                    capabilities=args.capability,
                    metadata=json.loads(args.metadata),
                ),
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "heartbeat-agent":
        emit(
            service.heartbeat_agent(
                args.agent_id,
                AgentHeartbeatRequest(status=args.status).status,
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "list-agents":
        emit([item.model_dump() for item in service.list_agents(args.workspace, principal=principal)])
        return

    if args.command == "create-task":
        emit(
            service.create_task(
                TaskCreateRequest(
                    workspace=args.workspace,
                    title=args.title,
                    description=args.description,
                    requested_by=args.requested_by,
                    assigned_to=args.assigned_to,
                    priority=args.priority,
                    labels=args.label,
                ),
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "list-tasks":
        emit(
            [
                item.model_dump()
                for item in service.list_tasks(args.workspace, args.status, principal=principal)
            ]
        )
        return

    if args.command == "claim-task":
        emit(
            service.claim_task(
                args.task_id,
                TaskClaimRequest(agent_id=args.agent_id),
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "complete-task":
        emit(
            service.complete_task(
                args.task_id,
                TaskCompleteRequest(agent_id=args.agent_id, result_summary=args.summary),
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "send-message":
        emit(
            service.post_message(
                MessageCreateRequest(
                    workspace=args.workspace,
                    sender_agent=args.sender_agent,
                    recipient_agent=args.recipient_agent,
                    task_id=args.task_id,
                    kind=args.kind,
                    content=args.content,
                    metadata=json.loads(args.metadata),
                ),
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "poll-messages":
        emit(
            [
                item.model_dump()
                for item in service.poll_messages(
                    workspace=args.workspace,
                    agent_id=args.agent_id,
                    limit=args.limit,
                    after=args.after,
                    principal=principal,
                )
            ]
        )
        return

    if args.command == "publish-artifact":
        emit(
            service.publish_artifact(
                ArtifactCreateRequest(
                    workspace=args.workspace,
                    author_agent=args.author_agent,
                    task_id=args.task_id,
                    message_id=args.message_id,
                    kind=args.kind,
                    uri=args.uri,
                    summary=args.summary,
                ),
                principal=principal,
            ).model_dump()
        )
        return

    if args.command == "timeline":
        emit([item.model_dump() for item in service.timeline(args.workspace, args.limit, principal=principal)])
        return

    parser.error(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    main()
