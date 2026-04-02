from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID

from rq import Queue
from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.core.db import register_after_commit_callback
from cve_service.models.entities import AIReview, AuditEvent, CVE, Classification
from cve_service.models.enums import AIReviewOutcome, AuditActorType, CveState
from cve_service.services.ai_review import fingerprint_payload

POST_ENRICHMENT_JOB_PATH = "cve_service.workers.jobs.process_post_enrichment_workflow_job"
ELIGIBLE_STATES = {CveState.CLASSIFIED, CveState.ENRICHMENT_PENDING, CveState.DEFERRED}


class PostEnrichmentJobProducer(Protocol):
    def schedule(
        self,
        session: Session,
        cve_id: str,
        *,
        trigger: str,
        requested_at: datetime | None = None,
        evaluated_at: datetime | None = None,
        retry_ai_review: bool = False,
        actor_type: AuditActorType = AuditActorType.SYSTEM,
    ) -> str | None:
        """Schedule post-enrichment processing after commit and return the job id when eligible."""


@dataclass(frozen=True, slots=True)
class RQPostEnrichmentJobProducer:
    queue: Queue
    database_url: str | None = None
    ai_payload: dict[str, Any] | str | None = None
    ai_model_name: str | None = None

    def schedule(
        self,
        session: Session,
        cve_id: str,
        *,
        trigger: str,
        requested_at: datetime | None = None,
        evaluated_at: datetime | None = None,
        retry_ai_review: bool = False,
        actor_type: AuditActorType = AuditActorType.SYSTEM,
    ) -> str | None:
        cve = _get_cve_by_public_id(session, cve_id)
        classification = _get_latest_classification(session, cve.id)
        if classification is None:
            raise ValueError(f"no classification found for {cve_id}")

        if cve.state not in ELIGIBLE_STATES:
            _write_enqueue_audit_event(
                session,
                cve=cve,
                actor_type=actor_type,
                event_type="workflow.post_enrichment_enqueue_skipped",
                details={
                    "trigger": trigger,
                    "queue_name": self.queue.name,
                    "retry_ai_review": retry_ai_review,
                    "skip_reason": f"state_ineligible:{cve.state.value}",
                },
            )
            return None

        latest_ai_review = _get_latest_ai_review(session, cve.id)
        if retry_ai_review:
            _validate_retry_override(cve, latest_ai_review)

        job_fingerprint = _build_job_fingerprint(
            cve=cve,
            classification=classification,
            latest_ai_review=latest_ai_review,
            retry_ai_review=retry_ai_review,
        )
        job_id = f"post-enrichment:{cve.cve_id}:{job_fingerprint[:16]}"
        existing_job = self.queue.fetch_job(job_id)
        event_type = "workflow.post_enrichment_enqueue_reused" if existing_job is not None else "workflow.post_enrichment_enqueue_requested"
        details = {
            "trigger": trigger,
            "queue_name": self.queue.name,
            "job_id": job_id,
            "job_fingerprint": job_fingerprint,
            "retry_ai_review": retry_ai_review,
            "classification_id": str(classification.id),
            "classification_outcome": classification.outcome.value,
            "state": cve.state.value,
            "evidence": {
                "poc_status": cve.poc_status.value,
                "poc_confidence": cve.poc_confidence,
                "itw_status": cve.itw_status.value,
                "itw_confidence": cve.itw_confidence,
            },
            "latest_ai_review_id": str(latest_ai_review.id) if latest_ai_review is not None else None,
            "latest_ai_review_outcome": latest_ai_review.outcome.value if latest_ai_review is not None else None,
            "requested_at": _serialize_datetime(requested_at),
            "evaluated_at": _serialize_datetime(evaluated_at),
        }
        if retry_ai_review and latest_ai_review is not None:
            details["retry_override_reason"] = (
                "invalid_previous_review" if latest_ai_review.schema_valid is False else "deferred_previous_review"
            )

        _write_enqueue_audit_event(
            session,
            cve=cve,
            actor_type=actor_type,
            event_type=event_type,
            details=details,
        )

        if existing_job is None:
            enqueue_kwargs = _build_enqueue_kwargs(
                requested_at=requested_at,
                evaluated_at=evaluated_at,
                retry_ai_review=retry_ai_review,
                database_url=self.database_url,
                ai_payload=self.ai_payload,
                ai_model_name=self.ai_model_name,
            )

            def enqueue_job() -> None:
                if self.queue.fetch_job(job_id) is not None:
                    return
                self.queue.enqueue(
                    POST_ENRICHMENT_JOB_PATH,
                    cve.cve_id,
                    job_id=job_id,
                    **enqueue_kwargs,
                )

            register_after_commit_callback(session, enqueue_job)

        return job_id


def _build_enqueue_kwargs(
    *,
    requested_at: datetime | None,
    evaluated_at: datetime | None,
    retry_ai_review: bool,
    database_url: str | None,
    ai_payload: dict[str, Any] | str | None,
    ai_model_name: str | None,
) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "retry_ai_review": retry_ai_review,
    }
    if database_url is not None:
        kwargs["database_url"] = database_url
    if requested_at is not None:
        kwargs["requested_at"] = _serialize_datetime(requested_at)
    if evaluated_at is not None:
        kwargs["evaluated_at"] = _serialize_datetime(evaluated_at)
    if ai_payload is not None:
        kwargs["ai_payload"] = ai_payload
    if ai_model_name is not None:
        kwargs["ai_model_name"] = ai_model_name
    return kwargs


def _build_job_fingerprint(
    *,
    cve: CVE,
    classification: Classification,
    latest_ai_review: AIReview | None,
    retry_ai_review: bool,
) -> str:
    payload: dict[str, Any] = {
        "cve_id": cve.cve_id,
        "state": cve.state.value,
        "classification_id": str(classification.id),
        "classification_outcome": classification.outcome.value,
        "reason_codes": list(classification.reason_codes),
        "evidence": {
            "poc_status": cve.poc_status.value,
            "poc_confidence": cve.poc_confidence,
            "itw_status": cve.itw_status.value,
            "itw_confidence": cve.itw_confidence,
        },
        "retry_ai_review": retry_ai_review,
    }
    if retry_ai_review and latest_ai_review is not None:
        payload["latest_ai_review"] = {
            "id": str(latest_ai_review.id),
            "schema_valid": latest_ai_review.schema_valid,
            "outcome": latest_ai_review.outcome.value,
        }
    return fingerprint_payload(payload)


def _validate_retry_override(cve: CVE, latest_ai_review: AIReview | None) -> None:
    if latest_ai_review is None:
        raise ValueError(f"retry_ai_review requires a prior AI review for {cve.cve_id}")
    if latest_ai_review.schema_valid is False:
        return
    if latest_ai_review.outcome is AIReviewOutcome.ADVISORY_DEFER:
        return
    raise ValueError(f"retry_ai_review is only allowed for invalid or advisory-defer AI outcomes: {cve.cve_id}")


def _get_cve_by_public_id(session: Session, cve_id: str) -> CVE:
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if cve is None:
        raise ValueError(f"unknown cve_id: {cve_id}")
    return cve


def _get_latest_classification(session: Session, cve_pk: UUID) -> Classification | None:
    return session.scalar(
        select(Classification)
        .where(Classification.cve_id == cve_pk)
        .order_by(Classification.created_at.desc(), Classification.id.desc())
        .limit(1)
    )


def _get_latest_ai_review(session: Session, cve_pk: UUID) -> AIReview | None:
    return session.scalar(
        select(AIReview)
        .where(AIReview.cve_id == cve_pk)
        .order_by(AIReview.created_at.desc(), AIReview.id.desc())
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
