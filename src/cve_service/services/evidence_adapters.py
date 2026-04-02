from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from cve_service.models.entities import Evidence
from cve_service.models.enums import EvidenceSignal, EvidenceSourceType, EvidenceStatus
from cve_service.services.enrichment import EvidenceInput, record_evidence


@dataclass(frozen=True, slots=True)
class VendorAdvisoryEvidence:
    cve_id: str
    vendor_name: str
    advisory_id: str
    signal_type: EvidenceSignal
    status: EvidenceStatus
    advisory_url: str | None = None
    published_at: datetime | None = None
    collected_at: datetime | None = None
    confidence: float = 0.95
    raw_payload: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class TrustedPoCEvidence:
    cve_id: str
    source_name: str
    source_record_id: str
    source_url: str | None = None
    observed_at: datetime | None = None
    collected_at: datetime | None = None
    status: EvidenceStatus = EvidenceStatus.PRESENT
    confidence: float = 0.9
    raw_payload: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class TrustedItwEvidence:
    cve_id: str
    source_name: str
    source_record_id: str
    source_url: str | None = None
    observed_at: datetime | None = None
    collected_at: datetime | None = None
    status: EvidenceStatus = EvidenceStatus.PRESENT
    confidence: float = 0.85
    raw_payload: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class KevEvidence:
    cve_id: str
    kev_catalog_id: str
    source_url: str | None = None
    date_added: datetime | None = None
    collected_at: datetime | None = None
    confidence: float = 1.0
    raw_payload: dict[str, Any] | None = None


def ingest_vendor_advisory_evidence(session: Session, advisory: VendorAdvisoryEvidence) -> Evidence:
    return record_evidence(
        session,
        EvidenceInput(
            cve_id=advisory.cve_id,
            signal_type=advisory.signal_type,
            status=advisory.status,
            source_name=advisory.vendor_name,
            source_type=EvidenceSourceType.VENDOR_ADVISORY,
            source_record_id=advisory.advisory_id,
            source_url=advisory.advisory_url,
            evidence_timestamp=advisory.published_at,
            collected_at=advisory.collected_at,
            freshness_ttl_seconds=14 * 24 * 60 * 60,
            confidence=advisory.confidence,
            is_authoritative=True,
            confidence_inputs={
                "adapter": "vendor_advisory",
                "vendor_name": advisory.vendor_name,
                "advisory_id": advisory.advisory_id,
                "base_confidence": advisory.confidence,
            },
            raw_payload=advisory.raw_payload,
        ),
    )


def ingest_trusted_poc_evidence(session: Session, poc: TrustedPoCEvidence) -> Evidence:
    return record_evidence(
        session,
        EvidenceInput(
            cve_id=poc.cve_id,
            signal_type=EvidenceSignal.POC,
            status=poc.status,
            source_name=poc.source_name,
            source_type=EvidenceSourceType.TRUSTED_POC,
            source_record_id=poc.source_record_id,
            source_url=poc.source_url,
            evidence_timestamp=poc.observed_at,
            collected_at=poc.collected_at,
            freshness_ttl_seconds=30 * 24 * 60 * 60,
            confidence=poc.confidence,
            is_authoritative=False,
            confidence_inputs={
                "adapter": "trusted_poc",
                "base_confidence": poc.confidence,
            },
            raw_payload=poc.raw_payload,
        ),
    )


def ingest_trusted_itw_evidence(session: Session, itw: TrustedItwEvidence) -> Evidence:
    return record_evidence(
        session,
        EvidenceInput(
            cve_id=itw.cve_id,
            signal_type=EvidenceSignal.ITW,
            status=itw.status,
            source_name=itw.source_name,
            source_type=EvidenceSourceType.TRUSTED_ITW,
            source_record_id=itw.source_record_id,
            source_url=itw.source_url,
            evidence_timestamp=itw.observed_at,
            collected_at=itw.collected_at,
            freshness_ttl_seconds=14 * 24 * 60 * 60,
            confidence=itw.confidence,
            is_authoritative=False,
            confidence_inputs={
                "adapter": "trusted_itw",
                "base_confidence": itw.confidence,
            },
            raw_payload=itw.raw_payload,
        ),
    )


def ingest_kev_evidence(session: Session, kev: KevEvidence) -> Evidence:
    return record_evidence(
        session,
        EvidenceInput(
            cve_id=kev.cve_id,
            signal_type=EvidenceSignal.ITW,
            status=EvidenceStatus.PRESENT,
            source_name="CISA KEV",
            source_type=EvidenceSourceType.KEV,
            source_record_id=kev.kev_catalog_id,
            source_url=kev.source_url,
            evidence_timestamp=kev.date_added,
            collected_at=kev.collected_at,
            freshness_ttl_seconds=45 * 24 * 60 * 60,
            confidence=kev.confidence,
            is_authoritative=True,
            confidence_inputs={
                "adapter": "kev",
                "base_confidence": kev.confidence,
                "kev_catalog_id": kev.kev_catalog_id,
            },
            raw_payload=kev.raw_payload,
        ),
    )
