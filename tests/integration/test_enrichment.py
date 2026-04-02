from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, Evidence
from cve_service.models.enums import AuditActorType, EvidenceSignal, EvidenceSourceType, EvidenceStatus
from cve_service.services.enrichment import (
    EvidenceInput,
    compute_enrichment_summary,
    find_stale_evidence_targets,
    record_evidence,
    refresh_stale_evidence,
)
from cve_service.services.evidence_adapters import (
    KevEvidence,
    TrustedItwEvidence,
    TrustedPoCEvidence,
    VendorAdvisoryEvidence,
    ingest_kev_evidence,
    ingest_trusted_itw_evidence,
    ingest_trusted_poc_evidence,
    ingest_vendor_advisory_evidence,
)
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record


def test_trusted_adapters_ingest_poc_and_itw_independently(session_factory) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0200"))

        poc_evidence = ingest_trusted_poc_evidence(
            session,
            TrustedPoCEvidence(
                cve_id="CVE-2026-0200",
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0200",
                source_url="https://example.test/poc/2026-0200",
                observed_at=datetime(2026, 4, 2, 13, 30, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 13, 35, tzinfo=UTC),
            ),
        )
        kev_evidence = ingest_kev_evidence(
            session,
            KevEvidence(
                cve_id="CVE-2026-0200",
                kev_catalog_id="kev-2026-0200",
                source_url="https://example.test/kev/2026-0200",
                date_added=datetime(2026, 4, 2, 13, 40, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 13, 41, tzinfo=UTC),
            ),
        )

        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0200"))
        evidence_items = session.scalars(select(Evidence).order_by(Evidence.signal_type.asc(), Evidence.source_name.asc())).all()

    assert cve is not None
    assert cve.poc_status is EvidenceStatus.PRESENT
    assert cve.poc_confidence == 0.9
    assert cve.itw_status is EvidenceStatus.PRESENT
    assert cve.itw_confidence == 1.0
    assert sorted(item.signal_type for item in evidence_items) == [EvidenceSignal.ITW, EvidenceSignal.POC]
    assert poc_evidence.source_type is EvidenceSourceType.TRUSTED_POC
    assert poc_evidence.source_record_id == "poc-2026-0200"
    assert poc_evidence.confidence_inputs["adapter"] == "trusted_poc"
    assert kev_evidence.source_type is EvidenceSourceType.KEV
    assert kev_evidence.source_record_id == "kev-2026-0200"
    assert kev_evidence.confidence_inputs["adapter"] == "kev"


def test_poc_and_itw_updates_do_not_overwrite_each_other(session_factory) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0201"))

        ingest_trusted_poc_evidence(
            session,
            TrustedPoCEvidence(
                cve_id="CVE-2026-0201",
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0201",
                observed_at=datetime(2026, 4, 2, 14, 10, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 14, 10, tzinfo=UTC),
                confidence=0.91,
            ),
        )
        ingest_trusted_itw_evidence(
            session,
            TrustedItwEvidence(
                cve_id="CVE-2026-0201",
                source_name="trusted-itw-feed",
                source_record_id="itw-2026-0201",
                observed_at=datetime(2026, 4, 2, 14, 12, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 14, 12, tzinfo=UTC),
                status=EvidenceStatus.ABSENT,
                confidence=0.83,
            ),
        )

        ingest_trusted_poc_evidence(
            session,
            TrustedPoCEvidence(
                cve_id="CVE-2026-0201",
                source_name="trusted-poc-db",
                source_record_id="poc-2026-0201",
                observed_at=datetime(2026, 4, 2, 14, 20, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 14, 20, tzinfo=UTC),
                status=EvidenceStatus.ABSENT,
                confidence=0.88,
            ),
        )

        after_poc_refresh = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0201"))
        evidence_after_poc_refresh = session.scalars(select(Evidence).order_by(Evidence.signal_type.asc())).all()
        after_poc_snapshot = (
            after_poc_refresh.poc_status,
            after_poc_refresh.poc_confidence,
            after_poc_refresh.itw_status,
            after_poc_refresh.itw_confidence,
        )

        ingest_trusted_itw_evidence(
            session,
            TrustedItwEvidence(
                cve_id="CVE-2026-0201",
                source_name="trusted-itw-feed",
                source_record_id="itw-2026-0201",
                observed_at=datetime(2026, 4, 2, 14, 25, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 14, 25, tzinfo=UTC),
                status=EvidenceStatus.PRESENT,
                confidence=0.84,
            ),
        )

        final_cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0201"))
        final_evidence_items = session.scalars(select(Evidence).order_by(Evidence.signal_type.asc())).all()

    assert after_poc_refresh is not None
    assert after_poc_snapshot == (
        EvidenceStatus.ABSENT,
        0.88,
        EvidenceStatus.ABSENT,
        0.83,
    )
    assert len(evidence_after_poc_refresh) == 2

    assert final_cve is not None
    assert final_cve.poc_status is EvidenceStatus.ABSENT
    assert final_cve.poc_confidence == 0.88
    assert final_cve.itw_status is EvidenceStatus.PRESENT
    assert final_cve.itw_confidence == 0.84
    assert len(final_evidence_items) == 2
    assert sorted(item.source_type for item in final_evidence_items) == [
        EvidenceSourceType.TRUSTED_ITW,
        EvidenceSourceType.TRUSTED_POC,
    ]


def test_freshness_aware_recompute_ignores_stale_evidence(session_factory) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0202"))

        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0202",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_record_id="stale-poc-2026-0202",
                evidence_timestamp=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                freshness_ttl_seconds=60 * 60,
                confidence=0.96,
                confidence_inputs={"base_confidence": 0.96},
            ),
        )
        vendor_evidence = ingest_vendor_advisory_evidence(
            session,
            VendorAdvisoryEvidence(
                cve_id="CVE-2026-0202",
                vendor_name="Microsoft",
                advisory_id="msrc-2026-0202",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.ABSENT,
                advisory_url="https://example.test/vendor/2026-0202",
                published_at=datetime(2026, 4, 2, 14, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 14, 0, tzinfo=UTC),
                confidence=0.93,
            ),
        )

        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0202"))
        rerun_summary = compute_enrichment_summary(session, "CVE-2026-0202")

    assert vendor_evidence.source_type is EvidenceSourceType.VENDOR_ADVISORY
    assert cve is not None
    assert cve.poc_status is EvidenceStatus.ABSENT
    assert cve.poc_confidence == 0.93
    assert rerun_summary.poc_status is EvidenceStatus.ABSENT
    assert rerun_summary.poc_confidence == 0.93


def test_low_confidence_evidence_fails_closed_and_summary_is_deterministic(session_factory) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0203"))

        ingest_trusted_itw_evidence(
            session,
            TrustedItwEvidence(
                cve_id="CVE-2026-0203",
                source_name="trusted-itw-feed",
                source_record_id="itw-2026-0203",
                observed_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                confidence=0.55,
            ),
        )

        first_summary = compute_enrichment_summary(session, "CVE-2026-0203")
        second_summary = compute_enrichment_summary(session, "CVE-2026-0203")
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0203"))

    assert first_summary == second_summary
    assert cve is not None
    assert cve.itw_status is EvidenceStatus.UNKNOWN
    assert cve.itw_confidence is None


def test_stale_evidence_targets_are_detected_for_aging_signal_only(session_factory) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0204"))
        ingest_public_feed_record(session, _record("CVE-2026-0205"))

        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0204",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_record_id="aging-poc-2026-0204",
                evidence_timestamp=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                freshness_ttl_seconds=60 * 60,
                confidence=0.91,
                confidence_inputs={"base_confidence": 0.91},
            ),
        )
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0205",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_record_id="fresh-poc-2026-0205",
                evidence_timestamp=datetime(2026, 4, 2, 12, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 12, 0, tzinfo=UTC),
                freshness_ttl_seconds=4 * 60 * 60,
                confidence=0.92,
                confidence_inputs={"base_confidence": 0.92},
            ),
        )

        targets = find_stale_evidence_targets(
            session,
            evaluated_at=datetime(2026, 4, 2, 12, 30, tzinfo=UTC),
        )

    assert [(target.cve_id, target.signal_type) for target in targets] == [
        ("CVE-2026-0204", EvidenceSignal.POC),
    ]
    assert targets[0].stale_records == 1
    assert targets[0].fresh_records == 0
    assert targets[0].qualified_records == 0


def test_refresh_stale_evidence_recomputes_summary_and_keeps_signals_separate(session_factory) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0206"))

        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0206",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_record_id="aging-poc-2026-0206",
                evidence_timestamp=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                freshness_ttl_seconds=60 * 60,
                confidence=0.96,
                confidence_inputs={"base_confidence": 0.96},
            ),
        )
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0206",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-itw-feed",
                source_type=EvidenceSourceType.TRUSTED_ITW,
                source_record_id="fresh-itw-2026-0206",
                evidence_timestamp=datetime(2026, 4, 2, 12, 15, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 12, 15, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.84,
                confidence_inputs={"base_confidence": 0.84},
            ),
        )

        result = refresh_stale_evidence(
            session,
            evaluated_at=datetime(2026, 4, 2, 12, 30, tzinfo=UTC),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0206"))
        evidence_items = session.scalars(select(Evidence).order_by(Evidence.signal_type.asc(), Evidence.created_at.asc())).all()
        audit_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.cve_id == cve.id)
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    assert result.stale_targets == 1
    assert result.recomputed_cves == 1
    assert result.cve_ids == ("CVE-2026-0206",)
    assert cve is not None
    assert cve.poc_status is EvidenceStatus.UNKNOWN
    assert cve.poc_confidence is None
    assert cve.itw_status is EvidenceStatus.PRESENT
    assert cve.itw_confidence == 0.84
    assert len(evidence_items) == 2

    refresh_event = next(event for event in audit_events if event.event_type == "enrichment.refresh_evaluated")
    summary_event = next(
        event
        for event in audit_events
        if event.event_type == "enrichment.summary_computed" and event.details["trigger"] == "stale_refresh"
    )
    assert refresh_event.actor_type is AuditActorType.WORKER
    assert refresh_event.details["signal_type"] == "POC"
    assert refresh_event.details["stale_records"] == 1
    assert refresh_event.details["action"] == "reevaluate_summary"
    assert summary_event.event_type == "enrichment.summary_computed"
    assert summary_event.details["trigger"] == "stale_refresh"
    assert summary_event.details["poc"]["status"] == "UNKNOWN"
    assert summary_event.details["poc"]["stale_records"] == 1
    assert summary_event.details["itw"]["status"] == "PRESENT"
    assert summary_event.details["itw"]["selected_source_record_id"] == "fresh-itw-2026-0206"


def test_conflicting_fresh_evidence_resolution_is_logged_and_reproducible(session_factory) -> None:
    with session_scope(session_factory) as session:
        ingest_public_feed_record(session, _record("CVE-2026-0207"))

        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0207",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_name="trusted-poc-db",
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_record_id="poc-present-2026-0207",
                evidence_timestamp=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.88,
                confidence_inputs={"base_confidence": 0.88},
            ),
        )
        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-0207",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.ABSENT,
                source_name="Microsoft",
                source_type=EvidenceSourceType.VENDOR_ADVISORY,
                source_record_id="poc-absent-2026-0207",
                evidence_timestamp=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.93,
                is_authoritative=True,
                confidence_inputs={"base_confidence": 0.93},
            ),
        )

        first_summary = compute_enrichment_summary(
            session,
            "CVE-2026-0207",
            evaluated_at=datetime(2026, 4, 2, 15, 10, tzinfo=UTC),
        )
        second_summary = compute_enrichment_summary(
            session,
            "CVE-2026-0207",
            evaluated_at=datetime(2026, 4, 2, 15, 10, tzinfo=UTC),
        )
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-0207"))
        conflict_events = session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.cve_id == cve.id,
                AuditEvent.event_type == "enrichment.signal_conflict_detected",
            )
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    assert first_summary == second_summary
    assert cve is not None
    assert cve.poc_status is EvidenceStatus.ABSENT
    assert cve.poc_confidence == 0.93
    assert len(conflict_events) >= 1
    latest_conflict_event = conflict_events[-1]
    assert latest_conflict_event.details["signal_type"] == "POC"
    assert latest_conflict_event.details["selected_status"] == "ABSENT"
    assert latest_conflict_event.details["selected_source_record_id"] == "poc-absent-2026-0207"
    assert latest_conflict_event.details["conflicting_records"] == [
        {
            "signal_type": "POC",
            "status": "PRESENT",
            "source_type": "TRUSTED_POC",
            "source_name": "trusted-poc-db",
            "source_record_id": "poc-present-2026-0207",
            "evidence_timestamp": "2026-04-02T15:00:00+00:00",
            "collected_at": "2026-04-02T15:00:00+00:00",
            "freshness_ttl_seconds": 1209600,
            "confidence": 0.88,
            "is_authoritative": False,
            "created_at": latest_conflict_event.details["conflicting_records"][0]["created_at"],
            "is_fresh": True,
            "is_qualified": True,
        }
    ]


def _record(cve_id: str) -> PublicFeedRecord:
    return PublicFeedRecord(
        cve_id=cve_id,
        title="Exchange Server RCE",
        description="Phase 2 evidence enrichment slice.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 13, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )
