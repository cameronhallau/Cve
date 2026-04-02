from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel

from cve_service.services.ingestion import IngestionResult, PublicFeedRecord, ingest_public_feed_record


class CveOrgRecordAdapter(BaseModel):
    source_name: str = "cve.org"

    def adapt(self, payload: dict[str, Any]) -> PublicFeedRecord:
        metadata = payload.get("cveMetadata", {})
        cna = payload.get("containers", {}).get("cna", {})
        affected = _first_affected_product(cna.get("affected", []))

        return PublicFeedRecord(
            source_name=self.source_name,
            source_record_id=metadata.get("cveId"),
            cve_id=metadata["cveId"],
            title=cna.get("title"),
            description=_english_description(cna.get("descriptions", [])),
            severity=_base_severity(cna.get("metrics", [])),
            source_published_at=_parse_datetime(metadata.get("datePublished")),
            source_modified_at=_parse_datetime(metadata.get("dateUpdated")),
            vendor_name=affected["vendor"],
            product_name=affected["product"],
            raw_payload=payload,
        )

    def adapt_many(self, payload: dict[str, Any]) -> list[PublicFeedRecord]:
        records = payload.get("cves", [])
        return [self.adapt(record) for record in records]


def ingest_cve_org_bundle(session, payload: dict[str, Any], adapter: CveOrgRecordAdapter | None = None) -> list[IngestionResult]:
    active_adapter = adapter or CveOrgRecordAdapter()
    return [ingest_public_feed_record(session, record) for record in active_adapter.adapt_many(payload)]


def _english_description(descriptions: list[dict[str, Any]]) -> str | None:
    for description in descriptions:
        if description.get("lang") == "en" and description.get("value"):
            return str(description["value"])
    return None


def _base_severity(metrics: list[dict[str, Any]]) -> str | None:
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            if key in metric and metric[key].get("baseSeverity"):
                return str(metric[key]["baseSeverity"])
    return None


def _first_affected_product(affected: list[dict[str, Any]]) -> dict[str, str]:
    for entry in affected:
        vendor = entry.get("vendor")
        product = entry.get("product")
        if vendor and product and product != "n/a":
            return {"vendor": str(vendor), "product": str(product)}
    raise ValueError("public feed record is missing an affected vendor/product pair")


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)
