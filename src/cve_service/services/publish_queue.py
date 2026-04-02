from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from rq import Queue
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.core.db import register_after_commit_callback
from cve_service.models.entities import AuditEvent, CVE, PolicyDecision
from cve_service.models.enums import AuditActorType, CveState, PolicyDecisionOutcome
from cve_service.services.publication import prepare_publication

PUBLISH_JOB_PATH = "cve_service.workers.jobs.process_publication_job"
ELIGIBLE_STATES = {CveState.PUBLISH_PENDING, CveState.UPDATE_PENDING}


class PublishJobProducer(Protocol):
    def schedule(
        self,
        session: Session,
        cve_id: str,
        *,
        trigger: str,
        requested_at: datetime | None = None,
        actor_type: AuditActorType = AuditActorType.SYSTEM,
    ) -> str | None:
        """Schedule publish processing after commit and return the job id when eligible."""


@dataclass(frozen=True, slots=True)
class RQPublishJobProducer:
    queue: Queue
    database_url: str | None = None
    publish_target_name: str = "console"
    publish_target_behavior: dict[str, Any] | None = None

    def schedule(
        self,
        session: Session,
        cve_id: str,
        *,
        trigger: str,
        requested_at: datetime | None = None,
        actor_type: AuditActorType = AuditActorType.SYSTEM,
    ) -> str | None:
        cve = _get_cve_by_public_id(session, cve_id)
        latest_decision = _get_latest_policy_decision(session, cve.id)
        if latest_decision is None or latest_decision.decision is not PolicyDecisionOutcome.PUBLISH:
            _write_enqueue_audit_event(
                session,
                cve=cve,
                actor_type=actor_type,
                event_type="workflow.publish_enqueue_skipped",
                details={
                    "trigger": trigger,
                    "queue_name": self.queue.name,
                    "target_name": self.publish_target_name,
                    "skip_reason": "no_publishable_policy_decision",
                },
            )
            return None

        if cve.state not in ELIGIBLE_STATES:
            _write_enqueue_audit_event(
                session,
                cve=cve,
                actor_type=actor_type,
                event_type="workflow.publish_enqueue_skipped",
                details={
                    "trigger": trigger,
                    "queue_name": self.queue.name,
                    "target_name": self.publish_target_name,
                    "skip_reason": f"state_ineligible:{cve.state.value}",
                },
            )
            return None

        prepared = prepare_publication(session, cve_id, target_name=self.publish_target_name)
        job_id = (
            f"publication:{prepared.event_type.value.lower()}:"
            f"{prepared.target_name}:{cve.cve_id}:{prepared.idempotency_key[:16]}"
        )
        existing_job = self.queue.fetch_job(job_id)
        event_type = "workflow.publish_enqueue_reused" if existing_job is not None else "workflow.publish_enqueue_requested"
        _write_enqueue_audit_event(
            session,
            cve=cve,
            actor_type=actor_type,
            event_type=event_type,
            details={
                "trigger": trigger,
                "queue_name": self.queue.name,
                "job_id": job_id,
                "target_name": prepared.target_name,
                "publication_event_type": prepared.event_type.value,
                "decision_id": str(prepared.decision.id) if prepared.decision is not None else None,
                "content_hash": prepared.content_hash,
                "idempotency_key": prepared.idempotency_key,
                "triggering_update_candidate_id": (
                    str(prepared.update_candidate.id) if prepared.update_candidate is not None else None
                ),
                "baseline_publication_event_id": (
                    str(prepared.baseline_publication_event.id)
                    if prepared.baseline_publication_event is not None
                    else None
                ),
                "requested_at": _serialize_datetime(requested_at),
            },
        )

        if existing_job is None:
            enqueue_kwargs = _build_enqueue_kwargs(
                requested_at=requested_at,
                database_url=self.database_url,
                publish_target_name=self.publish_target_name,
                publish_target_behavior=self.publish_target_behavior,
            )

            def enqueue_job() -> None:
                if self.queue.fetch_job(job_id) is not None:
                    return
                self.queue.enqueue(
                    PUBLISH_JOB_PATH,
                    cve.cve_id,
                    job_id=job_id,
                    **enqueue_kwargs,
                )

            register_after_commit_callback(session, enqueue_job)

        return job_id


def _build_enqueue_kwargs(
    *,
    requested_at: datetime | None,
    database_url: str | None,
    publish_target_name: str,
    publish_target_behavior: dict[str, Any] | None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "publish_target_name": publish_target_name,
    }
    if requested_at is not None:
        kwargs["attempted_at"] = _serialize_datetime(requested_at)
    if database_url is not None:
        kwargs["database_url"] = database_url
    if publish_target_behavior is not None:
        kwargs["publish_target_behavior"] = publish_target_behavior
    return kwargs


def _get_cve_by_public_id(session: Session, cve_id: str) -> CVE:
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if cve is None:
        raise ValueError(f"unknown cve_id: {cve_id}")
    return cve


def _get_latest_policy_decision(session: Session, cve_pk: UUID) -> PolicyDecision | None:
    return session.scalar(
        select(PolicyDecision)
        .where(PolicyDecision.cve_id == cve_pk)
        .order_by(PolicyDecision.created_at.desc(), PolicyDecision.id.desc())
        .limit(1)
    )


def _write_enqueue_audit_event(
    session: Session,
    *,
    cve: CVE,
    actor_type: AuditActorType,
    event_type: str,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="workflow",
            entity_id=None,
            actor_type=actor_type,
            actor_id=None,
            event_type=event_type,
            state_before=cve.state,
            state_after=cve.state,
            details=details,
        )
    )


def _serialize_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.isoformat()
