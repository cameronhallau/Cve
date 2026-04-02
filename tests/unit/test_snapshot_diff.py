from __future__ import annotations

from cve_service.services.snapshot_diff import compare_snapshots


def test_snapshot_diff_treats_source_metadata_as_non_material() -> None:
    previous = {
        "cve_id": "CVE-2026-0100",
        "severity": "HIGH",
        "source_modified_at": "2026-04-02T01:00:00+00:00",
        "product": {"canonical_name": "microsoft:exchange-server"},
    }
    current = {
        "cve_id": "CVE-2026-0100",
        "severity": "HIGH",
        "source_modified_at": "2026-04-02T02:00:00+00:00",
        "product": {"canonical_name": "microsoft:exchange-server"},
    }

    result = compare_snapshots(previous, current)

    assert result.is_material is False
    assert result.changed_fields == ("source_modified_at",)
    assert result.material_fields == ()
    assert result.non_material_fields == ("source_modified_at",)


def test_snapshot_diff_flags_content_delta_as_material() -> None:
    previous = {
        "cve_id": "CVE-2026-0101",
        "severity": "HIGH",
        "description": "Initial description",
        "product": {"canonical_name": "microsoft:exchange-server"},
    }
    current = {
        "cve_id": "CVE-2026-0101",
        "severity": "LOW",
        "description": "Updated description",
        "product": {"canonical_name": "microsoft:exchange-server"},
    }

    result = compare_snapshots(previous, current)

    assert result.is_material is True
    assert result.material_fields == ("description", "severity")


def test_snapshot_diff_treats_source_label_alias_changes_as_non_material() -> None:
    previous = {
        "cve_id": "CVE-2026-0102",
        "severity": "HIGH",
        "product": {
            "vendor_name": "Microsoft",
            "product_name": "Exchange Server",
            "canonical_name": "microsoft:exchange-server",
        },
        "source_labels": {
            "vendor_name": "Microsoft",
            "product_name": "Exchange Server",
        },
    }
    current = {
        "cve_id": "CVE-2026-0102",
        "severity": "HIGH",
        "product": {
            "vendor_name": "Microsoft",
            "product_name": "Exchange Server",
            "canonical_name": "microsoft:exchange-server",
        },
        "source_labels": {
            "vendor_name": "Microsoft Corporation",
            "product_name": "MS Exchange Server",
        },
    }

    result = compare_snapshots(previous, current)

    assert result.is_material is False
    assert result.changed_fields == ("source_labels.product_name", "source_labels.vendor_name")
    assert result.non_material_fields == ("source_labels.product_name", "source_labels.vendor_name")
