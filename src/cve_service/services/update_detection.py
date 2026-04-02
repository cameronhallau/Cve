from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AuditEvent, CVE, Classification, Evidence, PolicyDecision, PublicationEvent, UpdateCandidate
from cve_service.models.enums import AuditActorType, CveState, PublicationEventStatus
from cve_service.services.ai_review import fingerprint_payload
from cve_service.services.enrichment import SignalEvidenceRecord, summarize_signal_evidence
from cve_service.services.reason_codes import reason_code_registry_snapshot, validate_reason_codes
from cve_service.services.state_machine import InvalidStateTransition, guard_transition

if TYPE_CHECKING:
    from cve_service.services.publish_queue import PublishJobProducer

MATERIAL_CHANGE_COMPARATOR_VERSION = "phase5-material-change-comparator.v1"
NON_MATERIAL_METADATA_FIELDS: tuple[str, ...] = (
    "cve.title",
    "cve.description",
    "cve.source_published_at",
    "cve.source_modified_at",
)
MATERIAL_SIGNAL_RULES: tuple[tuple[str, str, str, str], ...] = (
    (
        "evidence.poc_status",
        "poc",
        "update.material.evidence_poc_status_changed",
        "Proof-of-concept status changed relative to the last published state.",
    ),
    (
        "evidence.itw_status",
        "itw",
        "update.material.evidence_itw_status_changed",
        "In-the-wild status changed relative to the last published state.",
    ),
)


@dataclass(frozen=True, slots=True)
class StateDelta:
    field: str
    before: Any
    after: Any
    material: bool
    reason_code: str | None
    explanation: str


@dataclass(frozen=True, slots=True)
class MaterialChangeComparison:
    comparison_fingerprint: str
    baseline_snapshot: dict[str, Any]
    current_snapshot: dict[str, Any]
    comparison_snapshot: dict[str, Any]
    material_changes: tuple[StateDelta, ...]
    non_material_changes: tuple[StateDelta, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UpdateCandidateDetectionResult:
    cve_id: str
    evaluated: bool
    state: CveState
    update_candidate_id: UUID | None
    baseline_publication_event_id: UUID | None
    material_change_detected: bool
    reason_codes: tuple[str, ...]
    comparison_fingerprint: str | None
    reused: bool
    publication_job_id: str | None


def compare_published_state(
    *,
    baseline_publication_event_id: UUID,
    baseline_snapshot: dict[str, Any],
    current_snapshot: dict[str, Any],
    trigger: str,
    evaluated_at: datetime,
) -> MaterialChangeComparison:
    material_changes: list[StateDelta] = []
    non_material_changes: list[StateDelta] = []

    for field_name, signal_name, reason_code, explanation in MATERIAL_SIGNAL_RULES:
        before = baseline_snapshot["evidence"][signal_name]["status"]
        after = current_snapshot["evidence"][signal_name]["status"]
        if before != after:
            material_changes.append(
                StateDelta(
                    field=field_name,
                    before=before,
                    after=after,
                    material=True,
                    reason_code=reason_code,
                    explanation=explanation,
                )
            )

    for field_name in NON_MATERIAL_METADATA_FIELDS:
        section_name, attribute_name = field_name.split(".", 1)
        before = baseline_snapshot[section_name][attribute_name]
        after = current_snapshot[section_name][attribute_name]
        if before != after:
            non_material_changes.append(
                StateDelta(
                    field=field_name,
                    before=before,
                    after=after,
                    material=False,
                    reason_code=None,
                    explanation="Metadata churn is recorded for replay but ignored for update-candidate creation.",
                )
            )

    reason_codes = tuple(validate_reason_codes(change.reason_code for change in material_changes if change.reason_code is not None))
    comparison_snapshot = {
        "schema_version": MATERIAL_CHANGE_COMPARATOR_VERSION,
        "trigger": trigger,
        "evaluated_at": _serialize_datetime(evaluated_at),
        "materiality_rules": {
            "rules_first": True,
            "ai_used_for_materiality": False,
            "material_fields": [rule[0] for rule in MATERIAL_SIGNAL_RULES],
            "non_material_fields": list(NON_MATERIAL_METADATA_FIELDS),
        },
        "baseline": baseline_snapshot,
        "current": current_snapshot,
        "changes": {
            "material": [_serialize_delta(change) for change in material_changes],
            "non_material": [_serialize_delta(change) for change in non_material_changes],
        },
        "reason_codes": list(reason_codes),
        "reason_code_definitions": reason_code_registry_snapshot(reason_codes),
    }
    comparison_fingerprint = fingerprint_payload(
        {
            "schema_version": MATERIAL_CHANGE_COMPARATOR_VERSION,
            "baseline_publication_event_id": str(baseline_publication_event_id),
            "reason_codes": list(reason_codes),
            "current_material_state": {
                "poc_status": current_snapshot["evidence"]["poc"]["status"],
                "itw_status": current_snapshot["evidence"]["itw"]["status"],
            },
        }
    )
    return MaterialChangeComparison(
        comparison_fingerprint=comparison_fingerprint,
        baseline_snapshot=baseline_snapshot,
        current_snapshot=current_snapshot,
        comparison_snapshot=comparison_snapshot,
        material_changes=tuple(material_changes),
        non_material_changes=tuple(non_material_changes),
        reason_codes=reason_codes,
    )


def detect_update_candidate(
    session: Session,
    cve_id: str,
    *,
    trigger: str,
    evaluated_at: datetime | None = None,
    actor_type: AuditActorType = AuditActorType.SYSTEM,
    publish_producer: PublishJobProducer | None = None,
) -> UpdateCandidateDetectionResult:
    cve = _get_cve_by_public_id(session, cve_id)
    if cve.state not in {CveState.PUBLISHED, CveState.UPDATE_PENDING}:
        return UpdateCandidateDetectionResult(
            cve_id=cve.cve_id,
            evaluated=False,
            state=cve.state,
            update_candidate_id=None,
            baseline_publication_event_id=None,
            material_change_detected=False,
            reason_codes=(),
            comparison_fingerprint=None,
            reused=False,
            publication_job_id=None,
        )

    baseline_publication = _get_latest_successful_publication_event(session, cve.id)
    if baseline_publication is None:
        return UpdateCandidateDetectionResult(
            cve_id=cve.cve_id,
            evaluated=False,
            state=cve.state,
            update_candidate_id=None,
            baseline_publication_event_id=None,
            material_change_detected=False,
            reason_codes=(),
            comparison_fingerprint=None,
            reused=False,
            publication_job_id=None,
        )

    effective_evaluated_at = _normalize_datetime(evaluated_at) or datetime.now(UTC)
    baseline_snapshot = _extract_published_state_snapshot(baseline_publication)
    current_snapshot = _build_current_state_snapshot(session, cve, effective_evaluated_at)
    comparison = compare_published_state(
        baseline_publication_event_id=baseline_publication.id,
        baseline_snapshot=baseline_snapshot,
        current_snapshot=current_snapshot,
        trigger=trigger,
        evaluated_at=effective_evaluated_at,
    )
    existing_candidate = _get_existing_update_candidate(session, cve.id, comparison.comparison_fingerprint)

    if not comparison.material_changes:
        _write_audit_event(
            session,
            cve=cve,
            entity_id=None,
            actor_type=actor_type,
            event_type="update_candidate.not_created",
            state_before=cve.state,
            state_after=cve.state,
            details={
                "trigger": trigger,
                "evaluated_at": _serialize_datetime(effective_evaluated_at),
                "baseline_publication_event_id": str(baseline_publication.id),
                "comparison_fingerprint": comparison.comparison_fingerprint,
                "material_change_detected": False,
                "material_change_codes": [],
                "non_material_changes": comparison.comparison_snapshot["changes"]["non_material"],
            },
        )
        session.flush()
        return UpdateCandidateDetectionResult(
            cve_id=cve.cve_id,
            evaluated=True,
            state=cve.state,
            update_candidate_id=None,
            baseline_publication_event_id=baseline_publication.id,
            material_change_detected=False,
            reason_codes=(),
            comparison_fingerprint=comparison.comparison_fingerprint,
            reused=False,
            publication_job_id=None,
        )

    state_before = cve.state
    cve.state = _resolve_state(cve.state, CveState.UPDATE_PENDING)

    if existing_candidate is not None:
        _write_audit_event(
            session,
            cve=cve,
            entity_id=existing_candidate.id,
            actor_type=actor_type,
            event_type="update_candidate.reused",
            state_before=state_before,
            state_after=cve.state,
            details={
                "trigger": trigger,
                "evaluated_at": _serialize_datetime(effective_evaluated_at),
                "baseline_publication_event_id": str(baseline_publication.id),
                "comparison_fingerprint": comparison.comparison_fingerprint,
                "reason_codes": list(existing_candidate.reason_codes),
                "reason_code_definitions": reason_code_registry_snapshot(existing_candidate.reason_codes),
                "material_changes": comparison.comparison_snapshot["changes"]["material"],
                "non_material_changes": comparison.comparison_snapshot["changes"]["non_material"],
                "reused": True,
            },
        )
        publication_job_id = _schedule_update_publication(
            session,
            cve=cve,
            publish_producer=publish_producer,
            requested_at=effective_evaluated_at,
            actor_type=actor_type,
        )
        session.flush()
        return UpdateCandidateDetectionResult(
            cve_id=cve.cve_id,
            evaluated=True,
            state=cve.state,
            update_candidate_id=existing_candidate.id,
            baseline_publication_event_id=baseline_publication.id,
            material_change_detected=True,
            reason_codes=tuple(existing_candidate.reason_codes),
            comparison_fingerprint=comparison.comparison_fingerprint,
            reused=True,
            publication_job_id=publication_job_id,
        )

    candidate = UpdateCandidate(
        cve_id=cve.id,
        publication_event_id=baseline_publication.id,
        comparison_fingerprint=comparison.comparison_fingerprint,
        comparator_version=MATERIAL_CHANGE_COMPARATOR_VERSION,
        reason_codes=list(comparison.reason_codes),
        comparison_snapshot=comparison.comparison_snapshot,
    )
    session.add(candidate)
    session.flush()

    _write_audit_event(
        session,
        cve=cve,
        entity_id=candidate.id,
        actor_type=actor_type,
        event_type="update_candidate.created",
        state_before=state_before,
        state_after=cve.state,
        details={
            "trigger": trigger,
            "evaluated_at": _serialize_datetime(effective_evaluated_at),
            "baseline_publication_event_id": str(baseline_publication.id),
            "comparison_fingerprint": comparison.comparison_fingerprint,
            "reason_codes": list(comparison.reason_codes),
            "reason_code_definitions": reason_code_registry_snapshot(comparison.reason_codes),
            "material_changes": comparison.comparison_snapshot["changes"]["material"],
            "non_material_changes": comparison.comparison_snapshot["changes"]["non_material"],
            "reused": False,
        },
    )
    publication_job_id = _schedule_update_publication(
        session,
        cve=cve,
        publish_producer=publish_producer,
        requested_at=effective_evaluated_at,
        actor_type=actor_type,
    )
    session.flush()
    return UpdateCandidateDetectionResult(
        cve_id=cve.cve_id,
        evaluated=True,
        state=cve.state,
        update_candidate_id=candidate.id,
        baseline_publication_event_id=baseline_publication.id,
        material_change_detected=True,
        reason_codes=comparison.reason_codes,
        comparison_fingerprint=comparison.comparison_fingerprint,
        reused=False,
        publication_job_id=publication_job_id,
    )


def _build_current_state_snapshot(session: Session, cve: CVE, evaluated_at: datetime) -> dict[str, Any]:
    classification = _get_latest_classification(session, cve.id)
    policy_decision = _get_latest_policy_decision(session, cve.id)
    evidence_items = session.scalars(
        select(Evidence).where(Evidence.cve_id == cve.id).order_by(Evidence.created_at.asc(), Evidence.id.asc())
    ).all()
    poc_summary = summarize_signal_evidence(
        [_as_signal_record(evidence) for evidence in evidence_items if evidence.signal_type.value == "POC"],
        evaluated_at=evaluated_at,
    )
    itw_summary = summarize_signal_evidence(
        [_as_signal_record(evidence) for evidence in evidence_items if evidence.signal_type.value == "ITW"],
        evaluated_at=evaluated_at,
    )
    return {
        "cve": {
            "cve_id": cve.cve_id,
            "title": cve.title,
            "description": cve.description,
            "severity": cve.severity,
            "source_published_at": _serialize_datetime(cve.source_published_at),
            "source_modified_at": _serialize_datetime(cve.source_modified_at),
            "state": cve.state.value,
        },
        "classification": {
            "id": str(classification.id) if classification is not None else None,
            "classifier_version": classification.classifier_version if classification is not None else None,
            "outcome": classification.outcome.value if classification is not None else None,
            "reason_codes": list(classification.reason_codes) if classification is not None else [],
            "canonical_name": classification.details.get("canonical_name") if classification is not None else None,
            "product_scope": classification.details.get("product_scope") if classification is not None else None,
        },
        "policy": {
            "last_policy_outcome": cve.last_policy_outcome.value if cve.last_policy_outcome is not None else None,
            "last_decision_at": _serialize_datetime(cve.last_decision_at),
            "latest_decision_id": str(policy_decision.id) if policy_decision is not None else None,
            "decision": policy_decision.decision.value if policy_decision is not None else None,
            "reason_codes": list(policy_decision.reason_codes) if policy_decision is not None else [],
            "policy_version": policy_decision.policy_version if policy_decision is not None else None,
            "policy_snapshot_id": str(policy_decision.policy_snapshot_id)
            if policy_decision is not None and policy_decision.policy_snapshot_id is not None
            else None,
        },
        "evidence": {
            "poc": _serialize_signal_summary(poc_summary),
            "itw": _serialize_signal_summary(itw_summary),
        },
    }


def _extract_published_state_snapshot(publication_event: PublicationEvent) -> dict[str, Any]:
    payload_snapshot = publication_event.payload_snapshot or {}
    replay_context = payload_snapshot.get("replay_context", {})
    publish_metadata = payload_snapshot.get("publish_content", {}).get("metadata", {})
    published_evidence = (replay_context.get("policy_decision") or {}).get("inputs_snapshot", {}).get("evidence", {})
    published_policy = replay_context.get("policy_decision", {})
    published_cve = replay_context.get("cve", {})
    published_classification = replay_context.get("classification", {})
    publication_lineage = replay_context.get("publication_lineage", {})
    return {
        "publication": {
            "event_id": str(publication_event.id),
            "event_type": publication_event.event_type.value,
            "published_at": _serialize_datetime(publication_event.published_at),
            "content_hash": publication_event.content_hash,
            "baseline_publication_event_id": publication_lineage.get("baseline_publication_event_id"),
            "lineage_root_publication_event_id": publication_lineage.get("lineage_root_publication_event_id"),
        },
        "cve": {
            "cve_id": published_cve.get("cve_id"),
            "title": published_cve.get("title"),
            "description": published_cve.get("description"),
            "severity": published_cve.get("severity"),
            "source_published_at": published_cve.get("source_published_at"),
            "source_modified_at": published_cve.get("source_modified_at"),
            "state": published_cve.get("state"),
        },
        "classification": {
            "id": published_classification.get("id"),
            "classifier_version": published_classification.get("classifier_version"),
            "outcome": published_classification.get("outcome"),
            "reason_codes": list(published_classification.get("reason_codes", [])),
            "canonical_name": published_classification.get("canonical_name", publish_metadata.get("canonical_name")),
            "product_scope": published_classification.get("product_scope", publish_metadata.get("product_scope")),
        },
        "policy": {
            "decision_id": published_policy.get("id"),
            "decision": published_policy.get("decision"),
            "reason_codes": list(published_policy.get("reason_codes", [])),
            "policy_version": published_policy.get("policy_version"),
            "policy_snapshot_id": published_policy.get("policy_snapshot_id"),
        },
        "evidence": {
            "poc": {
                "status": published_evidence.get("poc_status", publish_metadata.get("poc_status")),
                "confidence": published_evidence.get("poc_confidence", publish_metadata.get("poc_confidence")),
            },
            "itw": {
                "status": published_evidence.get("itw_status", publish_metadata.get("itw_status")),
                "confidence": published_evidence.get("itw_confidence", publish_metadata.get("itw_confidence")),
            },
        },
    }


def _serialize_signal_summary(summary) -> dict[str, Any]:
    return {
        "status": summary.status.value,
        "confidence": summary.confidence,
        "selected_source_type": summary.selected_source_type.value if summary.selected_source_type is not None else None,
        "selected_source_name": summary.selected_source_name,
        "selected_source_record_id": summary.selected_source_record_id,
        "evaluated_at": _serialize_datetime(summary.evaluated_at),
        "considered_records": summary.considered_records,
        "fresh_records": summary.fresh_records,
        "qualified_records": summary.qualified_records,
        "stale_records": summary.stale_records,
    }


def _serialize_delta(change: StateDelta) -> dict[str, Any]:
    return {
        "field": change.field,
        "before": change.before,
        "after": change.after,
        "material": change.material,
        "reason_code": change.reason_code,
        "explanation": change.explanation,
    }


def _as_signal_record(evidence: Evidence) -> SignalEvidenceRecord:
    return SignalEvidenceRecord(
        signal_type=evidence.signal_type,
        status=evidence.status,
        source_type=evidence.source_type,
        source_name=evidence.source_name,
        source_record_id=evidence.source_record_id,
        evidence_timestamp=evidence.evidence_timestamp,
        collected_at=evidence.collected_at,
        freshness_ttl_seconds=evidence.freshness_ttl_seconds,
        confidence=evidence.confidence,
        is_authoritative=evidence.is_authoritative,
        created_at=evidence.created_at,
    )


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


def _get_latest_policy_decision(session: Session, cve_pk: UUID) -> PolicyDecision | None:
    return session.scalar(
        select(PolicyDecision)
        .where(PolicyDecision.cve_id == cve_pk)
        .order_by(PolicyDecision.created_at.desc(), PolicyDecision.id.desc())
        .limit(1)
    )


def _get_latest_successful_publication_event(session: Session, cve_pk: UUID) -> PublicationEvent | None:
    return session.scalar(
        select(PublicationEvent)
        .where(
            PublicationEvent.cve_id == cve_pk,
            PublicationEvent.status == PublicationEventStatus.PUBLISHED,
        )
        .order_by(PublicationEvent.published_at.desc(), PublicationEvent.id.desc())
        .limit(1)
    )


def _get_existing_update_candidate(session: Session, cve_pk: UUID, comparison_fingerprint: str) -> UpdateCandidate | None:
    return session.scalar(
        select(UpdateCandidate)
        .where(
            UpdateCandidate.cve_id == cve_pk,
            UpdateCandidate.comparison_fingerprint == comparison_fingerprint,
        )
        .order_by(UpdateCandidate.created_at.desc(), UpdateCandidate.id.desc())
        .limit(1)
    )


def _write_audit_event(
    session: Session,
    *,
    cve: CVE,
    entity_id: UUID | None,
    actor_type: AuditActorType,
    event_type: str,
    state_before: CveState | None,
    state_after: CveState | None,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="update_candidate",
            entity_id=entity_id,
            actor_type=actor_type,
            actor_id=None,
            event_type=event_type,
            state_before=state_before,
            state_after=state_after,
            details=details,
        )
    )


def _schedule_update_publication(
    session: Session,
    *,
    cve: CVE,
    publish_producer: PublishJobProducer | None,
    requested_at: datetime,
    actor_type: AuditActorType,
) -> str | None:
    if publish_producer is None:
        return None
    return publish_producer.schedule(
        session,
        cve.cve_id,
        trigger="update_candidate_detected",
        requested_at=requested_at,
        actor_type=actor_type,
    )


def _resolve_state(current_state: CveState, desired_state: CveState) -> CveState:
    if current_state == desired_state:
        return current_state
    try:
        return guard_transition(current_state, desired_state)
    except InvalidStateTransition:
        return current_state


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _serialize_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
