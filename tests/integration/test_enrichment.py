from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, Evidence
from cve_service.models.enums import EvidenceSignal, EvidenceStatus
from cve_service.services.enrichment import EvidenceInput, compute_enrichment_summary, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record


def test_enrichment_summary_computes_poc_and_itw_independently(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0200",
        title="Exchange Server RCE",
        description="Phase 2 enrichment baseline.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 13, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, record)
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0200",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                evidence_timestamp=datetime(2026, 4, 2, 13, 30, tzinfo=UTC),
                confidence=0.9,
                is_authoritative=False,
            ),
        )
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0200",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.ABSENT,
                source_name="kev-check",
                evidence_timestamp=datetime(2026, 4, 2, 13, 35, tzinfo=UTC),
                confidence=0.2,
                is_authoritative=True,
            ),
        )
        summary = compute_enrichment_summary(session, "CVE-2026-0200")
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0200"))
        evidence_items = session.scalars(select(Evidence).order_by(Evidence.signal_type.asc())).all()
        audit_events = session.scalars(select(AuditEvent)).all()

    assert summary.poc_status is EvidenceStatus.PRESENT
    assert summary.poc_confidence == 0.9
    assert summary.itw_status is EvidenceStatus.ABSENT
    assert summary.itw_confidence == 0.2
    assert cve is not None
    assert cve.poc_status is EvidenceStatus.PRESENT
    assert cve.itw_status is EvidenceStatus.ABSENT
    assert sorted(item.signal_type for item in evidence_items) == [EvidenceSignal.ITW, EvidenceSignal.POC]
    assert sorted(event.event_type for event in audit_events) == [
        "classification.persisted",
        "enrichment.summary_computed",
        "evidence.recorded",
        "evidence.recorded",
        "ingestion.snapshot_created",
        "ingestion.snapshot_diffed",
    ]


def test_enrichment_summary_updates_itw_without_overwriting_existing_poc_summary(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0201",
        title="Exchange Server RCE",
        description="Independent signal update scenario.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 14, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )

    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, record)
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0201",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                evidence_timestamp=datetime(2026, 4, 2, 14, 10, tzinfo=UTC),
                confidence=0.8,
            ),
        )
        first_summary = compute_enrichment_summary(session, "CVE-2026-0201")
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0201",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_name="kev-check",
                evidence_timestamp=datetime(2026, 4, 2, 14, 20, tzinfo=UTC),
                confidence=0.95,
                is_authoritative=True,
            ),
        )
        second_summary = compute_enrichment_summary(session, "CVE-2026-0201")
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0201"))

    assert first_summary.poc_status is EvidenceStatus.PRESENT
    assert first_summary.itw_status is EvidenceStatus.UNKNOWN
    assert second_summary.poc_status is EvidenceStatus.PRESENT
    assert second_summary.poc_confidence == 0.8
    assert second_summary.itw_status is EvidenceStatus.PRESENT
    assert second_summary.itw_confidence == 0.95
    assert cve is not None
    assert cve.poc_status is EvidenceStatus.PRESENT
    assert cve.itw_status is EvidenceStatus.PRESENT
