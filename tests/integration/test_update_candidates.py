from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, PublicationEvent, UpdateCandidate
from cve_service.models.enums import CveState, EvidenceSignal, EvidenceSourceType, EvidenceStatus
from cve_service.services.enrichment import EvidenceInput, record_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publication import publish_initial_publication
from cve_service.services.publish_targets import InMemoryPublishTarget


class NeverCalledProvider:
    def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
        raise AssertionError("AI should not be called for deterministic candidates")


def test_no_update_candidate_is_created_for_published_metadata_only_churn(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5100", initial_signal=EvidenceSignal.POC)

        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-5100",
                title="Exchange Server RCE",
                description="Phase 5 update detection fixture.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 3, 0, 10, tzinfo=UTC),
                vendor_name="Microsoft",
                product_name="Exchange Server",
            ),
        )

        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5100"))
        update_candidates = session.scalars(select(UpdateCandidate)).all()
        audit_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.event_type == "update_candidate.not_created")
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    assert cve is not None
    assert cve.state is CveState.PUBLISHED
    assert update_candidates == []
    assert len(audit_events) == 1
    assert [change["field"] for change in audit_events[0].details["non_material_changes"]] == ["cve.source_modified_at"]


def test_poc_status_change_creates_update_candidate_for_published_cve(session_factory) -> None:
    with session_scope(session_factory) as session:
        publication_event = _prepare_published_cve(session, "CVE-2026-5101", initial_signal=EvidenceSignal.ITW)

        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-5101",
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_name="trusted-poc-db",
                source_record_id="poc-cve-2026-5101",
                evidence_timestamp=datetime(2026, 4, 3, 0, 15, tzinfo=UTC),
                collected_at=datetime(2026, 4, 3, 0, 15, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.95,
                raw_payload={"fixture": "poc-update"},
            ),
        )

        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5101"))
        candidate = session.scalar(select(UpdateCandidate))

    assert cve is not None
    assert candidate is not None
    assert cve.state is CveState.UPDATE_PENDING
    assert candidate.publication_event_id == publication_event.id
    assert candidate.reason_codes == ["update.material.evidence_poc_status_changed"]
    assert candidate.comparison_snapshot["baseline"]["evidence"]["poc"]["status"] == "UNKNOWN"
    assert candidate.comparison_snapshot["current"]["evidence"]["poc"]["status"] == "PRESENT"


def test_kev_backed_itw_change_creates_update_candidate(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5102", initial_signal=EvidenceSignal.POC)

        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-5102",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="cisa-kev",
                source_record_id="kev-cve-2026-5102",
                evidence_timestamp=datetime(2026, 4, 3, 0, 20, tzinfo=UTC),
                collected_at=datetime(2026, 4, 3, 0, 20, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.99,
                is_authoritative=True,
                raw_payload={"fixture": "kev-update"},
            ),
        )

        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-5102"))
        candidate = session.scalar(select(UpdateCandidate))

    assert cve is not None
    assert candidate is not None
    assert cve.state is CveState.UPDATE_PENDING
    assert candidate.reason_codes == ["update.material.evidence_itw_status_changed"]
    assert candidate.comparison_snapshot["current"]["evidence"]["itw"]["status"] == "PRESENT"
    assert candidate.comparison_snapshot["current"]["evidence"]["itw"]["selected_source_type"] == "KEV"


def test_unchanged_material_state_reuses_existing_update_candidate(session_factory) -> None:
    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5103", initial_signal=EvidenceSignal.POC)

        evidence_input = EvidenceInput(
            cve_id="CVE-2026-5103",
            signal_type=EvidenceSignal.ITW,
            status=EvidenceStatus.PRESENT,
            source_type=EvidenceSourceType.KEV,
            source_name="cisa-kev",
            source_record_id="kev-cve-2026-5103",
            evidence_timestamp=datetime(2026, 4, 3, 0, 25, tzinfo=UTC),
            collected_at=datetime(2026, 4, 3, 0, 25, tzinfo=UTC),
            freshness_ttl_seconds=14 * 24 * 60 * 60,
            confidence=0.99,
            is_authoritative=True,
            raw_payload={"fixture": "kev-update"},
        )
        record_evidence(session, evidence_input)
        record_evidence(session, evidence_input)

        candidates = session.scalars(select(UpdateCandidate).order_by(UpdateCandidate.created_at.asc())).all()
        reuse_events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.event_type == "update_candidate.reused")
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()

    assert len(candidates) == 1
    assert len(reuse_events) == 1
    assert reuse_events[0].details["reused"] is True


def test_update_candidate_stores_replayable_material_change_explanation(session_factory) -> None:
    with session_scope(session_factory) as session:
        publication_event = _prepare_published_cve(session, "CVE-2026-5104", initial_signal=EvidenceSignal.POC)

        record_evidence(
            session,
            EvidenceInput(
                cve_id="CVE-2026-5104",
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="cisa-kev",
                source_record_id="kev-cve-2026-5104",
                evidence_timestamp=datetime(2026, 4, 3, 0, 30, tzinfo=UTC),
                collected_at=datetime(2026, 4, 3, 0, 30, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.99,
                is_authoritative=True,
                raw_payload={"fixture": "kev-update"},
            ),
        )

        candidate = session.scalar(select(UpdateCandidate))

    assert candidate is not None
    assert candidate.publication_event_id == publication_event.id
    assert candidate.comparison_snapshot["schema_version"] == "phase5-material-change-comparator.v1"
    assert candidate.comparison_snapshot["baseline"]["publication"]["event_id"] == str(publication_event.id)
    assert candidate.comparison_snapshot["changes"]["material"][0]["field"] == "evidence.itw_status"
    assert candidate.comparison_snapshot["changes"]["material"][0]["explanation"] == (
        "In-the-wild status changed relative to the last published state."
    )
    assert candidate.comparison_snapshot["reason_code_definitions"][0]["code"] == "update.material.evidence_itw_status_changed"


def _prepare_published_cve(session, cve_id: str, *, initial_signal: EvidenceSignal) -> PublicationEvent:
    ingest_public_feed_record(
        session,
        PublicFeedRecord(
            cve_id=cve_id,
            title="Exchange Server RCE",
            description="Phase 5 update detection fixture.",
            severity="CRITICAL",
            source_name="fixture-feed",
            source_modified_at=datetime(2026, 4, 2, 23, 0, tzinfo=UTC),
            vendor_name="Microsoft",
            product_name="Exchange Server",
        ),
    )
    record_evidence(
        session,
        _initial_evidence_input(cve_id, initial_signal),
    )
    workflow_result = process_post_enrichment_workflow(
        session,
        cve_id,
        NeverCalledProvider(),
        requested_at=datetime(2026, 4, 2, 23, 10, tzinfo=UTC),
        evaluated_at=datetime(2026, 4, 2, 23, 10, tzinfo=UTC),
    )
    assert workflow_result.state is CveState.PUBLISH_PENDING

    publish_initial_publication(
        session,
        cve_id,
        InMemoryPublishTarget(name=f"phase5-initial-{cve_id.lower()}"),
        attempted_at=datetime(2026, 4, 2, 23, 20, tzinfo=UTC),
    )
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    assert cve is not None
    publication_event = session.scalar(
        select(PublicationEvent)
        .where(PublicationEvent.cve_id == cve.id)
        .order_by(PublicationEvent.published_at.desc(), PublicationEvent.id.desc())
    )
    assert publication_event is not None
    return publication_event


def _initial_evidence_input(cve_id: str, signal_type: EvidenceSignal) -> EvidenceInput:
    source_type = EvidenceSourceType.TRUSTED_POC if signal_type is EvidenceSignal.POC else EvidenceSourceType.TRUSTED_ITW
    source_name = "trusted-poc-db" if signal_type is EvidenceSignal.POC else "trusted-itw-db"
    source_record_id = f"{signal_type.value.lower()}-{cve_id.lower()}"
    return EvidenceInput(
        cve_id=cve_id,
        signal_type=signal_type,
        status=EvidenceStatus.PRESENT,
        source_type=source_type,
        source_name=source_name,
        source_record_id=source_record_id,
        evidence_timestamp=datetime(2026, 4, 2, 23, 5, tzinfo=UTC),
        collected_at=datetime(2026, 4, 2, 23, 5, tzinfo=UTC),
        freshness_ttl_seconds=14 * 24 * 60 * 60,
        confidence=0.93,
        raw_payload={"fixture": cve_id},
    )
