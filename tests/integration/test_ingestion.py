from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AuditEvent, CVE, CVEIngestionSnapshot, Classification
from cve_service.models.enums import ClassificationOutcome, CveState
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.public_feed import ingest_cve_org_bundle


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
        audit_events = session.scalars(select(AuditEvent)).all()

    assert first.snapshot_created is True
    assert first.classification_created is True
    assert first.diff_evaluated is True
    assert first.state is CveState.CLASSIFIED
    assert second.snapshot_created is False
    assert second.classification_created is False
    assert second.diff_evaluated is False
    assert second.classifier_version == first.classifier_version
    assert second.reason_codes == first.reason_codes
    assert len(snapshots) == 1
    assert len(classifications) == 1
    assert sorted(event.event_type for event in audit_events) == [
        "classification.persisted",
        "classification.reused",
        "ingestion.idempotent_reuse",
        "ingestion.snapshot_created",
        "ingestion.snapshot_diffed",
    ]


def test_consumer_only_products_are_denied_and_persist_classifier_trace(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0002",
        title="Archer Router takeover",
        description="Critical consumer router issue.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 2, 0, tzinfo=UTC),
        vendor_name="TPLINK",
        product_name="AX50 Wireless Router",
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
    assert stored.details["product_registry_version"] == "product-registry.v1"
    assert stored.snapshot_id is not None
    assert stored.details["canonical_name"] == "tp-link:archer-ax50"
    assert cve is not None
    assert cve.state is CveState.SUPPRESSED


def test_non_critical_dos_records_are_suppressed_during_ingestion(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0003",
        title="Junos OS denial of service vulnerability",
        description="A denial of service issue lets remote attackers crash flowd repeatedly.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 3, 0, tzinfo=UTC),
        vendor_name="Juniper Networks",
        product_name="Junos OS",
    )

    with session_scope(session_factory) as session:
        result = ingest_public_feed_record(session, record)
        stored = session.get(Classification, result.classification_id)
        cve = session.scalar(select(CVE).where(CVE.cve_id == record.cve_id))

    assert result.state is CveState.SUPPRESSED
    assert stored is not None
    assert stored.outcome is ClassificationOutcome.DENY
    assert stored.reason_codes == ["classifier.deny.non_critical_denial_of_service"]
    assert cve is not None
    assert cve.state is CveState.SUPPRESSED


def test_alias_only_rename_reingest_keeps_same_canonical_identity_without_classification_drift(session_factory) -> None:
    initial = PublicFeedRecord(
        cve_id="CVE-2026-0006",
        title="Exchange Server RCE",
        description="Alias stability scenario.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 8, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )
    alias_rename = PublicFeedRecord(
        cve_id="CVE-2026-0006",
        title="Exchange Server RCE",
        description="Alias stability scenario.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 9, 0, tzinfo=UTC),
        vendor_name="Microsoft Corporation",
        product_name="MS Exchange Server",
    )

    with session_scope(session_factory) as session:
        first = ingest_public_feed_record(session, initial)
        second = ingest_public_feed_record(session, alias_rename)
        snapshots = session.scalars(
            select(CVEIngestionSnapshot).order_by(CVEIngestionSnapshot.snapshot_index.asc())
        ).all()
        classifications = session.scalars(select(Classification)).all()
        audit_events = session.scalars(select(AuditEvent)).all()

    assert first.classification_created is True
    assert second.snapshot_created is True
    assert second.classification_created is False
    assert second.material_change_detected is False
    assert second.diff_material_fields == ()
    assert sorted(second.diff_changed_fields) == [
        "source_labels.product_name",
        "source_labels.vendor_name",
        "source_modified_at",
    ]
    assert len(snapshots) == 2
    assert snapshots[0].normalized_payload["product"]["canonical_name"] == "microsoft:exchange-server"
    assert snapshots[1].normalized_payload["product"]["canonical_name"] == "microsoft:exchange-server"
    assert len(classifications) == 1
    assert classifications[0].details["canonical_name"] == "microsoft:exchange-server"
    assert classifications[0].details["canonical_vendor_name"] == "Microsoft"
    assert classifications[0].details["canonical_product_name"] == "Exchange Server"
    assert classifications[0].details["product_registry_version"] == "product-registry.v1"
    assert sorted(event.event_type for event in audit_events) == [
        "classification.persisted",
        "classification.skipped_non_material_churn",
        "ingestion.snapshot_created",
        "ingestion.snapshot_created",
        "ingestion.snapshot_diffed",
        "ingestion.snapshot_diffed",
    ]


def test_material_change_creates_retained_snapshot_and_reclassifies(session_factory) -> None:
    initial = PublicFeedRecord(
        cve_id="CVE-2026-0004",
        title="Exchange Server RCE",
        description="Initial enterprise impact.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 4, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )
    changed = PublicFeedRecord(
        cve_id="CVE-2026-0004",
        title="Exchange Server RCE",
        description="Vendor revision expands the affected build list.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 5, 0, tzinfo=UTC),
        vendor_name="Microsoft Corporation",
        product_name="MS Exchange Server",
    )

    with session_scope(session_factory) as session:
        first = ingest_public_feed_record(session, initial)
        second = ingest_public_feed_record(session, changed)
        snapshots = session.scalars(
            select(CVEIngestionSnapshot).order_by(CVEIngestionSnapshot.snapshot_index.asc())
        ).all()
        classifications = session.scalars(select(Classification)).all()
        audit_events = session.scalars(select(AuditEvent)).all()
        cve = session.scalar(select(CVE).where(CVE.cve_id == initial.cve_id))

    classifications = sorted(classifications, key=lambda item: item.details["snapshot_index"])
    assert first.classification_created is True
    assert second.snapshot_created is True
    assert second.classification_created is True
    assert second.material_change_detected is True
    assert set(second.diff_material_fields) == {"description"}
    assert len(snapshots) == 2
    assert snapshots[1].previous_snapshot_id == snapshots[0].id
    assert len(classifications) == 2
    assert classifications[0].outcome is ClassificationOutcome.CANDIDATE
    assert classifications[1].outcome is ClassificationOutcome.CANDIDATE
    assert classifications[1].details["reclassification_trigger"] == "material_snapshot_change"
    assert classifications[0].details["canonical_name"] == "microsoft:exchange-server"
    assert classifications[1].details["canonical_name"] == "microsoft:exchange-server"
    assert classifications[1].snapshot_id == snapshots[1].id
    assert cve is not None
    assert cve.state is CveState.CLASSIFIED
    assert sorted(event.event_type for event in audit_events) == [
        "classification.persisted",
        "classification.reclassified",
        "ingestion.snapshot_created",
        "ingestion.snapshot_created",
        "ingestion.snapshot_diffed",
        "ingestion.snapshot_diffed",
    ]


def test_non_material_metadata_churn_retains_snapshot_without_reclassification(session_factory) -> None:
    initial = PublicFeedRecord(
        cve_id="CVE-2026-0005",
        title="Exchange Server RCE",
        description="Metadata churn scenario.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 6, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )
    metadata_only = PublicFeedRecord(
        cve_id="CVE-2026-0005",
        title="Exchange Server RCE",
        description="Metadata churn scenario.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 7, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )

    with session_scope(session_factory) as session:
        first = ingest_public_feed_record(session, initial)
        second = ingest_public_feed_record(session, metadata_only)
        snapshots = session.scalars(
            select(CVEIngestionSnapshot).order_by(CVEIngestionSnapshot.snapshot_index.asc())
        ).all()
        classifications = session.scalars(select(Classification)).all()
        audit_events = session.scalars(select(AuditEvent)).all()
        cve = session.scalar(select(CVE).where(CVE.cve_id == initial.cve_id))

    assert first.classification_created is True
    assert second.snapshot_created is True
    assert second.classification_created is False
    assert second.material_change_detected is False
    assert second.diff_changed_fields == ("source_modified_at",)
    assert second.diff_material_fields == ()
    assert len(snapshots) == 2
    assert snapshots[1].previous_snapshot_id == snapshots[0].id
    assert len(classifications) == 1
    assert cve is not None
    assert cve.state is CveState.CLASSIFIED
    assert sorted(event.event_type for event in audit_events) == [
        "classification.persisted",
        "classification.skipped_non_material_churn",
        "ingestion.snapshot_created",
        "ingestion.snapshot_created",
        "ingestion.snapshot_diffed",
        "ingestion.snapshot_diffed",
    ]


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
        cve = session.scalar(select(CVE).where(CVE.cve_id == record.cve_id))
        audit_events = session.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "classification.persisted")
        ).all()

    assert result.ai_route_eligible is True
    assert result.ai_route_allowed is True
    assert stored is not None
    assert cve is not None
    assert stored.outcome is ClassificationOutcome.NEEDS_AI
    assert stored.classifier_version == "deterministic-classifier.v1"
    assert stored.reason_codes == ["classifier.needs_ai.unknown_product_scope"]
    assert stored.details["ai_route"] == {
        "eligible": True,
        "allowed": True,
        "blocked_reason": None,
    }
    assert cve.state is CveState.CLASSIFIED
    assert len(audit_events) == 1
    assert audit_events[0].details["outcome"] == "NEEDS_AI"


def test_classification_records_are_linked_to_exact_source_snapshot(session_factory) -> None:
    record = PublicFeedRecord(
        cve_id="CVE-2026-0007",
        title="Exchange Server RCE",
        description="Trace linkage scenario.",
        severity="CRITICAL",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
        vendor_name="Microsoft",
        product_name="Exchange Server",
    )

    with session_scope(session_factory) as session:
        result = ingest_public_feed_record(session, record)
        classification = session.get(Classification, result.classification_id)
        snapshot = session.scalar(select(CVEIngestionSnapshot).where(CVEIngestionSnapshot.snapshot_index == 1))
        audit_events = session.scalars(select(AuditEvent)).all()

    assert classification is not None
    assert snapshot is not None
    assert classification.snapshot_id == snapshot.id
    assert classification.details["snapshot_id"] == str(snapshot.id)
    assert sorted(event.event_type for event in audit_events) == [
        "classification.persisted",
        "ingestion.snapshot_created",
        "ingestion.snapshot_diffed",
    ]


def test_cve_org_public_feed_bundle_uses_deterministic_ingestion_path(session_factory) -> None:
    bundle = {
        "cves": [
            {
                "cveMetadata": {
                    "cveId": "CVE-2026-0008",
                    "datePublished": "2026-04-02T11:00:00Z",
                    "dateUpdated": "2026-04-02T11:30:00Z",
                },
                "containers": {
                    "cna": {
                        "title": "Exchange Server RCE",
                        "descriptions": [{"lang": "en", "value": "Critical Exchange Server issue."}],
                        "affected": [{"vendor": "Microsoft Corporation", "product": "MS Exchange Server"}],
                        "metrics": [{"cvssV3_1": {"baseSeverity": "CRITICAL"}}],
                    }
                },
            },
            {
                "cveMetadata": {
                    "cveId": "CVE-2026-0009",
                    "datePublished": "2026-04-02T12:00:00Z",
                    "dateUpdated": "2026-04-02T12:30:00Z",
                },
                "containers": {
                    "cna": {
                        "title": "Consumer router issue",
                        "descriptions": [{"lang": "en", "value": "Critical Archer AX50 issue."}],
                        "affected": [{"vendor": "TPLINK", "product": "AX50 Wireless Router"}],
                        "metrics": [{"cvssV3_1": {"baseSeverity": "CRITICAL"}}],
                    }
                },
            },
        ]
    }

    with session_scope(session_factory) as session:
        results = ingest_cve_org_bundle(session, bundle)
        cves = session.scalars(select(CVE).order_by(CVE.cve_id.asc())).all()
        classifications = session.scalars(select(Classification).order_by(Classification.created_at.asc())).all()
        audit_events = session.scalars(select(AuditEvent)).all()

    assert [result.cve_id for result in results] == ["CVE-2026-0008", "CVE-2026-0009"]
    assert results[0].state is CveState.CLASSIFIED
    assert results[1].state is CveState.SUPPRESSED
    assert [cve.state for cve in cves] == [CveState.CLASSIFIED, CveState.SUPPRESSED]
    assert classifications[0].details["canonical_name"] == "microsoft:exchange-server"
    assert classifications[1].details["canonical_name"] == "tp-link:archer-ax50"
    assert classifications[0].reason_codes == ["classifier.candidate.enterprise_high_or_critical"]
    assert classifications[1].reason_codes == ["classifier.deny.consumer_only_product"]
    assert all(classification.classifier_version == "deterministic-classifier.v1" for classification in classifications)
    assert sorted(event.event_type for event in audit_events) == [
        "classification.persisted",
        "classification.persisted",
        "ingestion.snapshot_created",
        "ingestion.snapshot_created",
        "ingestion.snapshot_diffed",
        "ingestion.snapshot_diffed",
    ]
