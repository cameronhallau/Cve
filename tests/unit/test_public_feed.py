from __future__ import annotations

from cve_service.services.public_feed import CveOrgRecordAdapter


def test_cve_org_adapter_maps_record_to_public_feed_record() -> None:
    payload = {
        "cveMetadata": {
            "cveId": "CVE-2026-1000",
            "datePublished": "2026-04-02T08:00:00Z",
            "dateUpdated": "2026-04-02T09:30:00Z",
        },
        "containers": {
            "cna": {
                "title": "Exchange Server RCE",
                "descriptions": [{"lang": "en", "value": "Critical Exchange Server issue."}],
                "affected": [{"vendor": "Microsoft Corporation", "product": "MS Exchange Server"}],
                "metrics": [{"cvssV3_1": {"baseSeverity": "CRITICAL"}}],
            }
        },
    }

    record = CveOrgRecordAdapter().adapt(payload)

    assert record.source_name == "cve.org"
    assert record.cve_id == "CVE-2026-1000"
    assert record.vendor_name == "Microsoft Corporation"
    assert record.product_name == "MS Exchange Server"
    assert record.severity == "CRITICAL"


def test_cve_org_adapter_maps_bundle_to_multiple_records() -> None:
    bundle = {
        "cves": [
            {
                "cveMetadata": {"cveId": "CVE-2026-1001"},
                "containers": {
                    "cna": {
                        "affected": [{"vendor": "TP-Link", "product": "Archer AX50 Router"}],
                    }
                },
            },
            {
                "cveMetadata": {"cveId": "CVE-2026-1002"},
                "containers": {
                    "cna": {
                        "affected": [{"vendor": "Cisco Systems", "product": "Cisco ASA"}],
                    }
                },
            },
        ]
    }

    records = CveOrgRecordAdapter().adapt_many(bundle)

    assert [record.cve_id for record in records] == ["CVE-2026-1001", "CVE-2026-1002"]
