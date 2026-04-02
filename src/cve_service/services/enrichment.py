from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AuditEvent, CVE, Evidence
from cve_service.models.enums import AuditActorType, EvidenceSignal, EvidenceSourceType, EvidenceStatus

LOW_CONFIDENCE_THRESHOLD = 0.6
DEFAULT_FRESHNESS_TTL_SECONDS = 30 * 24 * 60 * 60


@dataclass(frozen=True, slots=True)
class EvidenceInput:
    cve_id: str
    signal_type: EvidenceSignal
    status: EvidenceStatus
    source_name: str
    source_type: EvidenceSourceType = EvidenceSourceType.OTHER
    source_record_id: str | None = None
    source_url: str | None = None
    evidence_timestamp: datetime | None = None
    collected_at: datetime | None = None
    freshness_ttl_seconds: int = DEFAULT_FRESHNESS_TTL_SECONDS
    confidence: float | None = None
    is_authoritative: bool = False
    confidence_inputs: dict[str, Any] | None = None
    raw_payload: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class EnrichmentSummary:
    cve_id: str
    poc_status: EvidenceStatus
    poc_confidence: float | None
    itw_status: EvidenceStatus
    itw_confidence: float | None


@dataclass(frozen=True, slots=True)
class SignalEvidenceRecord:
    signal_type: EvidenceSignal
    status: EvidenceStatus
    source_type: EvidenceSourceType
    source_name: str
    source_record_id: str
    evidence_timestamp: datetime | None
    collected_at: datetime
    freshness_ttl_seconds: int
    confidence: float | None
    is_authoritative: bool
    created_at: datetime


@dataclass(frozen=True, slots=True)
class SignalSummaryComputation:
    status: EvidenceStatus
    confidence: float | None
    selected_source_type: EvidenceSourceType | None
    selected_source_name: str | None
    selected_source_record_id: str | None
    evaluated_at: datetime | None
    considered_records: int
    fresh_records: int
    qualified_records: int
    stale_records: int


def record_evidence(session: Session, evidence_input: EvidenceInput) -> Evidence:
    cve = _get_cve_by_public_id(session, evidence_input.cve_id)
    normalized_input = _normalize_evidence_input(evidence_input)
    existing_evidence = _latest_evidence_by_source_identity(
        session,
        cve.id,
        normalized_input.signal_type,
        normalized_input.source_type,
        normalized_input.source_name,
        normalized_input.source_record_id,
    )

    if existing_evidence is None:
        evidence = Evidence(
            cve_id=cve.id,
            signal_type=normalized_input.signal_type,
            source_type=normalized_input.source_type,
            status=normalized_input.status,
            source_name=normalized_input.source_name,
            source_record_id=normalized_input.source_record_id,
            source_url=normalized_input.source_url,
            evidence_timestamp=normalized_input.evidence_timestamp,
            collected_at=normalized_input.collected_at,
            freshness_ttl_seconds=normalized_input.freshness_ttl_seconds,
            confidence=normalized_input.confidence,
            is_authoritative=normalized_input.is_authoritative,
            confidence_inputs=normalized_input.confidence_inputs or {},
            raw_payload=normalized_input.raw_payload or {},
        )
        session.add(evidence)
        session.flush()

        _write_evidence_audit_event(
            session,
            cve=cve,
            evidence=evidence,
            event_type="evidence.recorded",
            details=_serialize_evidence(evidence),
        )
    else:
        previous_state = _serialize_evidence(existing_evidence)
        existing_evidence.status = normalized_input.status
        existing_evidence.source_url = normalized_input.source_url
        existing_evidence.evidence_timestamp = normalized_input.evidence_timestamp
        existing_evidence.collected_at = normalized_input.collected_at
        existing_evidence.freshness_ttl_seconds = normalized_input.freshness_ttl_seconds
        existing_evidence.confidence = normalized_input.confidence
        existing_evidence.is_authoritative = normalized_input.is_authoritative
        existing_evidence.confidence_inputs = normalized_input.confidence_inputs or {}
        existing_evidence.raw_payload = normalized_input.raw_payload or {}
        session.flush()

        evidence = existing_evidence
        _write_evidence_audit_event(
            session,
            cve=cve,
            evidence=evidence,
            event_type="evidence.updated",
            details={
                "before": previous_state,
                "after": _serialize_evidence(evidence),
            },
        )

    compute_enrichment_summary(session, evidence_input.cve_id)
    return evidence


def compute_enrichment_summary(session: Session, cve_id: str) -> EnrichmentSummary:
    cve = _get_cve_by_public_id(session, cve_id)
    evidence_items = session.scalars(
        select(Evidence).where(Evidence.cve_id == cve.id).order_by(Evidence.created_at.asc(), Evidence.id.asc())
    ).all()

    poc_summary = summarize_signal_evidence(
        [
            _as_signal_record(evidence)
            for evidence in evidence_items
            if evidence.signal_type == EvidenceSignal.POC
        ]
    )
    itw_summary = summarize_signal_evidence(
        [
            _as_signal_record(evidence)
            for evidence in evidence_items
            if evidence.signal_type == EvidenceSignal.ITW
        ]
    )

    cve.poc_status = poc_summary.status
    cve.poc_confidence = poc_summary.confidence
    cve.itw_status = itw_summary.status
    cve.itw_confidence = itw_summary.confidence
    session.flush()

    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="cve",
            entity_id=cve.id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            event_type="enrichment.summary_computed",
            state_before=cve.state,
            state_after=cve.state,
            details={
                "poc": _serialize_signal_summary(poc_summary),
                "itw": _serialize_signal_summary(itw_summary),
            },
        )
    )
    session.flush()

    return EnrichmentSummary(
        cve_id=cve.cve_id,
        poc_status=cve.poc_status,
        poc_confidence=cve.poc_confidence,
        itw_status=cve.itw_status,
        itw_confidence=cve.itw_confidence,
    )


def summarize_signal_evidence(evidence_items: Sequence[SignalEvidenceRecord]) -> SignalSummaryComputation:
    if not evidence_items:
        return SignalSummaryComputation(
            status=EvidenceStatus.UNKNOWN,
            confidence=None,
            selected_source_type=None,
            selected_source_name=None,
            selected_source_record_id=None,
            evaluated_at=None,
            considered_records=0,
            fresh_records=0,
            qualified_records=0,
            stale_records=0,
        )

    evaluated_at = max(item.collected_at for item in evidence_items)
    fresh_records = [item for item in evidence_items if _is_fresh(item, evaluated_at)]
    qualified_records = [item for item in fresh_records if _is_confident(item)]

    if not qualified_records:
        return SignalSummaryComputation(
            status=EvidenceStatus.UNKNOWN,
            confidence=None,
            selected_source_type=None,
            selected_source_name=None,
            selected_source_record_id=None,
            evaluated_at=evaluated_at,
            considered_records=len(evidence_items),
            fresh_records=len(fresh_records),
            qualified_records=0,
            stale_records=len(evidence_items) - len(fresh_records),
        )

    selected = sorted(qualified_records, key=_signal_sort_key, reverse=True)[0]
    return SignalSummaryComputation(
        status=selected.status,
        confidence=selected.confidence,
        selected_source_type=selected.source_type,
        selected_source_name=selected.source_name,
        selected_source_record_id=selected.source_record_id,
        evaluated_at=evaluated_at,
        considered_records=len(evidence_items),
        fresh_records=len(fresh_records),
        qualified_records=len(qualified_records),
        stale_records=len(evidence_items) - len(fresh_records),
    )


def _normalize_evidence_input(evidence_input: EvidenceInput) -> EvidenceInput:
    collected_at = _normalize_datetime(evidence_input.collected_at) or _normalize_datetime(evidence_input.evidence_timestamp)
    if collected_at is None:
        collected_at = datetime.now(UTC)

    if evidence_input.freshness_ttl_seconds <= 0:
        raise ValueError("freshness_ttl_seconds must be positive")

    confidence = evidence_input.confidence
    if confidence is not None and not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")

    source_record_id = evidence_input.source_record_id or evidence_input.source_url or evidence_input.source_name
    confidence_inputs = {
        "source_type": evidence_input.source_type.value,
        "low_confidence_threshold": LOW_CONFIDENCE_THRESHOLD,
        "freshness_ttl_seconds": evidence_input.freshness_ttl_seconds,
        **(evidence_input.confidence_inputs or {}),
    }

    return EvidenceInput(
        cve_id=evidence_input.cve_id,
        signal_type=evidence_input.signal_type,
        status=evidence_input.status,
        source_name=evidence_input.source_name,
        source_type=evidence_input.source_type,
        source_record_id=source_record_id,
        source_url=evidence_input.source_url,
        evidence_timestamp=_normalize_datetime(evidence_input.evidence_timestamp),
        collected_at=collected_at,
        freshness_ttl_seconds=evidence_input.freshness_ttl_seconds,
        confidence=confidence,
        is_authoritative=evidence_input.is_authoritative,
        confidence_inputs=confidence_inputs,
        raw_payload=evidence_input.raw_payload or {},
    )


def _latest_evidence_by_source_identity(
    session: Session,
    cve_pk,
    signal_type: EvidenceSignal,
    source_type: EvidenceSourceType,
    source_name: str,
    source_record_id: str,
) -> Evidence | None:
    return session.scalar(
        select(Evidence)
        .where(
            Evidence.cve_id == cve_pk,
            Evidence.signal_type == signal_type,
            Evidence.source_type == source_type,
            Evidence.source_name == source_name,
            Evidence.source_record_id == source_record_id,
        )
        .order_by(Evidence.created_at.desc(), Evidence.id.desc())
        .limit(1)
    )


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


def _signal_sort_key(evidence: SignalEvidenceRecord) -> tuple[Any, ...]:
    confidence = evidence.confidence if evidence.confidence is not None else -1.0
    evidence_timestamp = evidence.evidence_timestamp or datetime.min.replace(tzinfo=UTC)
    created_at = _normalize_datetime(evidence.created_at) or datetime.min.replace(tzinfo=UTC)
    return (
        confidence,
        evidence.is_authoritative,
        evidence_timestamp,
        created_at,
        evidence.source_type.value,
        evidence.source_name,
        evidence.source_record_id,
    )


def _is_confident(evidence: SignalEvidenceRecord) -> bool:
    return evidence.confidence is not None and evidence.confidence >= LOW_CONFIDENCE_THRESHOLD


def _is_fresh(evidence: SignalEvidenceRecord, evaluated_at: datetime) -> bool:
    return evidence.collected_at + timedelta(seconds=evidence.freshness_ttl_seconds) >= evaluated_at


def _serialize_evidence(evidence: Evidence) -> dict[str, Any]:
    return {
        "signal_type": evidence.signal_type.value,
        "source_type": evidence.source_type.value,
        "status": evidence.status.value,
        "source_name": evidence.source_name,
        "source_record_id": evidence.source_record_id,
        "source_url": evidence.source_url,
        "evidence_timestamp": _serialize_datetime(evidence.evidence_timestamp),
        "collected_at": _serialize_datetime(evidence.collected_at),
        "freshness_ttl_seconds": evidence.freshness_ttl_seconds,
        "confidence": evidence.confidence,
        "is_authoritative": evidence.is_authoritative,
        "confidence_inputs": evidence.confidence_inputs,
    }


def _serialize_signal_summary(summary: SignalSummaryComputation) -> dict[str, Any]:
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


def _write_evidence_audit_event(
    session: Session,
    *,
    cve: CVE,
    evidence: Evidence,
    event_type: str,
    details: dict[str, Any],
) -> None:
    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="evidence",
            entity_id=evidence.id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            event_type=event_type,
            state_before=cve.state,
            state_after=cve.state,
            details=details,
        )
    )
    session.flush()


def _normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _serialize_datetime(value: datetime | None) -> str | None:
    normalized = _normalize_datetime(value)
    return normalized.isoformat() if normalized is not None else None


def _get_cve_by_public_id(session: Session, cve_id: str) -> CVE:
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if cve is None:
        raise ValueError(f"unknown CVE ID: {cve_id}")
    return cve
