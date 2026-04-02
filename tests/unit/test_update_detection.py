from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from cve_service.services.update_detection import compare_published_state


def _baseline_snapshot() -> dict:
    return {
        "publication": {
            "event_id": str(uuid4()),
            "event_type": "INITIAL",
            "published_at": "2026-04-02T23:00:00+00:00",
            "content_hash": "baseline-hash",
        },
        "cve": {
            "cve_id": "CVE-2026-5000",
            "title": "Exchange Server RCE",
            "description": "Baseline description",
            "severity": "CRITICAL",
            "source_published_at": "2026-04-02T20:00:00+00:00",
            "source_modified_at": "2026-04-02T21:00:00+00:00",
            "state": "PUBLISHED",
        },
        "policy": {
            "decision_id": str(uuid4()),
            "decision": "PUBLISH",
            "reason_codes": ["policy.publish.enterprise_candidate_with_poc"],
            "policy_version": "phase4-policy.v1",
            "policy_snapshot_id": str(uuid4()),
        },
        "evidence": {
            "poc": {
                "status": "ABSENT",
                "confidence": None,
            },
            "itw": {
                "status": "ABSENT",
                "confidence": None,
            },
        },
    }


def _current_snapshot() -> dict:
    return {
        "cve": {
            "cve_id": "CVE-2026-5000",
            "title": "Exchange Server RCE",
            "description": "Baseline description",
            "severity": "CRITICAL",
            "source_published_at": "2026-04-02T20:00:00+00:00",
            "source_modified_at": "2026-04-02T21:00:00+00:00",
            "state": "PUBLISHED",
        },
        "classification": {
            "id": str(uuid4()),
            "classifier_version": "classifier.v1",
            "outcome": "CANDIDATE",
            "reason_codes": ["classifier.candidate.enterprise_high_or_critical"],
        },
        "policy": {
            "last_policy_outcome": "PUBLISH",
            "last_decision_at": "2026-04-02T22:00:00+00:00",
            "latest_decision_id": str(uuid4()),
            "decision": "PUBLISH",
            "reason_codes": ["policy.publish.enterprise_candidate_with_poc"],
            "policy_version": "phase4-policy.v1",
            "policy_snapshot_id": str(uuid4()),
        },
        "evidence": {
            "poc": {
                "status": "ABSENT",
                "confidence": None,
                "selected_source_type": None,
                "selected_source_name": None,
                "selected_source_record_id": None,
                "evaluated_at": "2026-04-02T23:10:00+00:00",
                "considered_records": 0,
                "fresh_records": 0,
                "qualified_records": 0,
                "stale_records": 0,
            },
            "itw": {
                "status": "ABSENT",
                "confidence": None,
                "selected_source_type": None,
                "selected_source_name": None,
                "selected_source_record_id": None,
                "evaluated_at": "2026-04-02T23:10:00+00:00",
                "considered_records": 0,
                "fresh_records": 0,
                "qualified_records": 0,
                "stale_records": 0,
            },
        },
    }


def test_compare_published_state_ignores_metadata_only_churn() -> None:
    baseline = _baseline_snapshot()
    current = _current_snapshot()
    current["cve"]["source_modified_at"] = "2026-04-02T23:15:00+00:00"
    current["cve"]["description"] = "Updated metadata only"

    comparison = compare_published_state(
        baseline_publication_event_id=uuid4(),
        baseline_snapshot=baseline,
        current_snapshot=current,
        trigger="unit-test",
        evaluated_at=datetime(2026, 4, 2, 23, 15, tzinfo=UTC),
    )

    assert comparison.reason_codes == ()
    assert comparison.material_changes == ()
    assert [change.field for change in comparison.non_material_changes] == [
        "cve.description",
        "cve.source_modified_at",
    ]
    assert comparison.comparison_snapshot["changes"]["material"] == []


def test_compare_published_state_marks_poc_signal_delta_as_material() -> None:
    baseline = _baseline_snapshot()
    current = _current_snapshot()
    current["evidence"]["poc"]["status"] = "PRESENT"

    comparison = compare_published_state(
        baseline_publication_event_id=uuid4(),
        baseline_snapshot=baseline,
        current_snapshot=current,
        trigger="unit-test",
        evaluated_at=datetime(2026, 4, 2, 23, 20, tzinfo=UTC),
    )

    assert comparison.reason_codes == ("update.material.evidence_poc_status_changed",)
    assert [change.field for change in comparison.material_changes] == ["evidence.poc_status"]
    assert comparison.comparison_snapshot["reason_code_definitions"][0]["code"] == "update.material.evidence_poc_status_changed"


def test_compare_published_state_keeps_replayable_material_explanation() -> None:
    baseline = _baseline_snapshot()
    current = _current_snapshot()
    current["evidence"]["itw"]["status"] = "PRESENT"

    comparison = compare_published_state(
        baseline_publication_event_id=uuid4(),
        baseline_snapshot=baseline,
        current_snapshot=current,
        trigger="unit-test",
        evaluated_at=datetime(2026, 4, 2, 23, 30, tzinfo=UTC),
    )

    material_change = comparison.comparison_snapshot["changes"]["material"][0]

    assert material_change["field"] == "evidence.itw_status"
    assert material_change["before"] == "ABSENT"
    assert material_change["after"] == "PRESENT"
    assert "relative to the last published state" in material_change["explanation"]
