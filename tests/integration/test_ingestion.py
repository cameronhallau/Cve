from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, CVEIngestionSnapshot, Classification
from cve_service.models.enums import ClassificationOutcome, CveState
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record


def test_reingest_of_same_cve_is_idempotent(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0001",
        title="Exchange Server RCE",
        description="Critical unauthenticated RCE in Exchange Server.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 1, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
        raw_payload={"id": "CVE-2026-0001", "severity": "CRITICAL"},
    )

    with session_scope(session_factory) as session:
        first = ingest_public_feed_record(session, record)
        second = ingest_public_feed_record(session, record)

        snapshots = session.scalars(select(CVEIngestionSnapshot)).all()
        classifications = session.scalars(select(Classification)).all()
        audit_events = session.scalars(select(AuditEvent).order_by(AuditEvent.created_at.asc())).all()

    assert first.snapshot_created is True
    assert first.classification_created is True
    assert first.state is CveState.CLASSIFIED
    assert second.snapshot_created is False
    assert second.classification_created is False
    assert second.classifier_version == first.classifier_version
    assert second.reason_codes == first.reason_codes
    assert len(snapshots) == 1
    assert len(classifications) == 1
    assert [event.event_type for event in audit_events] == [
        "ingestion.snapshot_created",
        "classification.persisted",
        "ingestion.idempotent_reuse",
        "classification.reused",
    ]


def test_consumer_only_products_are_denied_and_persist_classifier_trace(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0002",
        title="Archer Router takeover",
        description="Critical consumer router issue.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 2, 0, tzinfo=UTC),
        vendor_name="TP-Link",
        product_name="Archer AX50 Router",
    )

    with session_scope(session_factory) as session:
        result = ingest_public_feed_record(session, record)
        stored = session.get(Classification, result.classification_id)
        cve = session.scalar(select(CVE).where(CVE.cve_id == record.cve_id))

    assert result.state is CveState.SUPPRESSED
    assert stored is not None
    assert stored.outcome is ClassificationOutcome.DENY
    assert stored.classifier_version == "deterministic-classifier.v1"
    assert stored.reason_codes == ["classifier.deny.consumer_only_product"]
    assert stored.details["reason_code_registry_version"] == "reason-codes.v1"
    assert cve is not None
    assert cve.state is CveState.SUPPRESSED


def test_classifier_persists_before_ai_route_is_considered(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0003",
        title="Ambiguous gateway issue",
        description="High severity issue in an unclear product line.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 3, 0, tzinfo=UTC),
        vendor_name="Acme",
        product_name="Widget Gateway",
    )

    with session_scope(session_factory) as session:
        result = ingest_public_feed_record(session, record)
        stored = session.get(Classification, result.classification_id)
        audit_events = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "classification.persisted")
        ).all()

    assert result.ai_route_eligible is True
    assert result.ai_route_allowed is False
    assert stored is not None
    assert stored.outcome is ClassificationOutcome.NEEDS_AI
    assert stored.classifier_version == "deterministic-classifier.v1"
    assert stored.reason_codes == [
        "classifier.needs_ai.unknown_product_scope",
        "classifier.fail_closed.ai_out_of_scope",
    ]
    assert stored.details["ai_route"] == {
        "eligible": True,
        "allowed": False,
        "blocked_reason": "phase1_ai_out_of_scope",
    }
    assert len(audit_events) == 1
    assert audit_events[0].details["outcome"] == "NEEDS_AI"
