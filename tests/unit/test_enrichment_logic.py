from __future__ import annotations

from datetime import UTC, datetime

from cve_service.models.enums import EvidenceSignal, EvidenceSourceType, EvidenceStatus
from cve_service.services.enrichment import SignalEvidenceRecord, summarize_signal_evidence


def test_summarize_signal_evidence_ignores_stale_records() -> None:
    summary = summarize_signal_evidence(
        [
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_name="trusted-poc-db",
                source_record_id="old",
                evidence_timestamp=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                freshness_ttl_seconds=60 * 60,
                confidence=0.97,
                is_authoritative=False,
                created_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
            ),
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.ABSENT,
                source_type=EvidenceSourceType.VENDOR_ADVISORY,
                source_name="Microsoft",
                source_record_id="new",
                evidence_timestamp=datetime(2026, 4, 2, 14, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 14, 0, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.93,
                is_authoritative=True,
                created_at=datetime(2026, 4, 2, 14, 0, tzinfo=UTC),
            ),
        ]
    )

    assert summary.status is EvidenceStatus.ABSENT
    assert summary.confidence == 0.93
    assert summary.selected_source_type is EvidenceSourceType.VENDOR_ADVISORY
    assert summary.stale_records == 1


def test_summarize_signal_evidence_fails_closed_below_threshold() -> None:
    summary = summarize_signal_evidence(
        [
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.TRUSTED_ITW,
                source_name="trusted-itw-feed",
                source_record_id="itw",
                evidence_timestamp=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.55,
                is_authoritative=False,
                created_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
            )
        ]
    )

    assert summary.status is EvidenceStatus.UNKNOWN
    assert summary.confidence is None
    assert summary.qualified_records == 0


def test_summarize_signal_evidence_prefers_higher_confidence_same_signal() -> None:
    summary = summarize_signal_evidence(
        [
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.ABSENT,
                source_type=EvidenceSourceType.TRUSTED_ITW,
                source_name="trusted-itw-feed",
                source_record_id="feed-absent",
                evidence_timestamp=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.7,
                is_authoritative=False,
                created_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
            ),
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.KEV,
                source_name="CISA KEV",
                source_record_id="kev-present",
                evidence_timestamp=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
                freshness_ttl_seconds=45 * 24 * 60 * 60,
                confidence=1.0,
                is_authoritative=True,
                created_at=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
            ),
        ]
    )

    assert summary.status is EvidenceStatus.PRESENT
    assert summary.confidence == 1.0
    assert summary.selected_source_type is EvidenceSourceType.KEV


def test_summarize_signal_evidence_explicit_evaluated_at_ages_out_old_records() -> None:
    summary = summarize_signal_evidence(
        [
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.TRUSTED_POC,
                source_name="trusted-poc-db",
                source_record_id="stale-present",
                evidence_timestamp=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
                freshness_ttl_seconds=60 * 60,
                confidence=0.99,
                is_authoritative=False,
                created_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC),
            ),
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.POC,
                status=EvidenceStatus.ABSENT,
                source_type=EvidenceSourceType.VENDOR_ADVISORY,
                source_name="Microsoft",
                source_record_id="fresh-absent",
                evidence_timestamp=datetime(2026, 4, 2, 12, 15, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 12, 15, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.61,
                is_authoritative=True,
                created_at=datetime(2026, 4, 2, 12, 15, tzinfo=UTC),
            ),
        ],
        evaluated_at=datetime(2026, 4, 2, 12, 30, tzinfo=UTC),
    )

    assert summary.status is EvidenceStatus.ABSENT
    assert summary.confidence == 0.61
    assert summary.selected_source_record_id == "fresh-absent"
    assert summary.stale_records == 1


def test_summarize_signal_evidence_tracks_conflicting_fresh_records() -> None:
    summary = summarize_signal_evidence(
        [
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.PRESENT,
                source_type=EvidenceSourceType.TRUSTED_ITW,
                source_name="trusted-itw-feed",
                source_record_id="itw-present",
                evidence_timestamp=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
                freshness_ttl_seconds=14 * 24 * 60 * 60,
                confidence=0.88,
                is_authoritative=False,
                created_at=datetime(2026, 4, 2, 15, 0, tzinfo=UTC),
            ),
            SignalEvidenceRecord(
                signal_type=EvidenceSignal.ITW,
                status=EvidenceStatus.ABSENT,
                source_type=EvidenceSourceType.KEV,
                source_name="CISA KEV",
                source_record_id="itw-absent",
                evidence_timestamp=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
                collected_at=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
                freshness_ttl_seconds=45 * 24 * 60 * 60,
                confidence=0.9,
                is_authoritative=True,
                created_at=datetime(2026, 4, 2, 15, 5, tzinfo=UTC),
            ),
        ]
    )

    assert summary.status is EvidenceStatus.ABSENT
    assert summary.selected_source_record_id == "itw-absent"
    assert len(summary.conflicting_records) == 1
    assert summary.conflicting_records[0].source_record_id == "itw-present"
