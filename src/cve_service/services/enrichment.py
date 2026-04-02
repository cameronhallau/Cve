from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cve_service.models.entities import AuditEvent, CVE, Evidence
from cve_service.models.enums import AuditActorType, EvidenceSignal, EvidenceStatus


@dataclass(frozen=True, slots=True)
class EvidenceInput:
    cve_id: str
    signal_type: EvidenceSignal
    status: EvidenceStatus
    source_name: str
    source_url: str | None = None
    evidence_timestamp: datetime | None = None
    confidence: float | None = None
    is_authoritative: bool = False
    raw_payload: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class EnrichmentSummary:
    cve_id: str
    poc_status: EvidenceStatus
    poc_confidence: float | None
    itw_status: EvidenceStatus
    itw_confidence: float | None


def record_evidence(session: Session, evidence_input: EvidenceInput) -> Evidence:
    cve = _get_cve_by_public_id(session, evidence_input.cve_id)
    evidence = Evidence(
        cve_id=cve.id,
        signal_type=evidence_input.signal_type,
        status=evidence_input.status,
        source_name=evidence_input.source_name,
        source_url=evidence_input.source_url,
        evidence_timestamp=evidence_input.evidence_timestamp,
        confidence=evidence_input.confidence,
        is_authoritative=evidence_input.is_authoritative,
        raw_payload=evidence_input.raw_payload or {},
    )
    session.add(evidence)
    session.flush()

    session.add(
        AuditEvent(
            cve_id=cve.id,
            entity_type="evidence",
            entity_id=evidence.id,
            actor_type=AuditActorType.SYSTEM,
            actor_id=None,
            event_type="evidence.recorded",
            state_before=cve.state,
            state_after=cve.state,
            details={
                "signal_type": evidence.signal_type.value,
                "status": evidence.status.value,
                "source_name": evidence.source_name,
                "confidence": evidence.confidence,
                "is_authoritative": evidence.is_authoritative,
            },
        )
    )
    session.flush()
    return evidence


def compute_enrichment_summary(session: Session, cve_id: str) -> EnrichmentSummary:
    cve = _get_cve_by_public_id(session, cve_id)
    poc_summary = _latest_signal_summary(session, cve.id, EvidenceSignal.POC)
    itw_summary = _latest_signal_summary(session, cve.id, EvidenceSignal.ITW)

    cve.poc_status = poc_summary["status"]
    cve.poc_confidence = poc_summary["confidence"]
    cve.itw_status = itw_summary["status"]
    cve.itw_confidence = itw_summary["confidence"]
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
                "poc_status": cve.poc_status.value,
                "poc_confidence": cve.poc_confidence,
                "itw_status": cve.itw_status.value,
                "itw_confidence": cve.itw_confidence,
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


def _latest_signal_summary(session: Session, cve_pk, signal_type: EvidenceSignal) -> dict[str, EvidenceStatus | float | None]:
    evidence = session.scalar(
        select(Evidence)
        .where(Evidence.cve_id == cve_pk, Evidence.signal_type == signal_type)
        .order_by(
            Evidence.is_authoritative.desc(),
            Evidence.evidence_timestamp.desc().nullslast(),
            Evidence.created_at.desc(),
        )
        .limit(1)
    )
    if evidence is None:
        return {"status": EvidenceStatus.UNKNOWN, "confidence": None}

    return {"status": evidence.status, "confidence": evidence.confidence}


def _get_cve_by_public_id(session: Session, cve_id: str) -> CVE:
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if cve is None:
        raise ValueError(f"unknown CVE ID: {cve_id}")
    return cve
