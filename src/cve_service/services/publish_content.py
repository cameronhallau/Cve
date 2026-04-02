from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve_service.models.entities import AIReview, CVE, Classification, PolicyDecision
from cve_service.models.enums import EvidenceStatus

PUBLISH_CONTENT_SCHEMA_VERSION = "phase4-initial-publication.v1"


@dataclass(frozen=True, slots=True)
class PublishContent:
    schema_version: str
    title: str
    summary: str
    body: str
    labels: tuple[str, ...]
    metadata: dict[str, Any]

    def as_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "title": self.title,
            "summary": self.summary,
            "body": self.body,
            "labels": list(self.labels),
            "metadata": self.metadata,
        }


def build_initial_publish_content(
    *,
    cve: CVE,
    classification: Classification,
    decision: PolicyDecision,
    ai_review: AIReview | None,
) -> PublishContent:
    canonical_name = classification.details.get("canonical_name")
    product_scope = classification.details.get("product_scope")
    evidence_label = _derive_evidence_label(cve.poc_status, cve.itw_status)
    title = f"{cve.cve_id}: {cve.title or 'Untitled vulnerability'}"
    summary = " | ".join(
        part
        for part in (
            cve.severity or "UNKNOWN",
            canonical_name or "unknown-product",
            evidence_label,
        )
        if part
    )
    body_lines = [
        f"CVE: {cve.cve_id}",
        f"Severity: {cve.severity or 'UNKNOWN'}",
        f"Product: {canonical_name or 'unknown-product'}",
        f"Product Scope: {product_scope or 'unknown'}",
        f"Policy Decision: {decision.decision.value}",
        f"Policy Reasons: {', '.join(decision.reason_codes) if decision.reason_codes else 'none'}",
        (
            f"Exploit Evidence: PoC={cve.poc_status.value} ({_format_confidence(cve.poc_confidence)}), "
            f"ITW={cve.itw_status.value} ({_format_confidence(cve.itw_confidence)})"
        ),
        f"AI Advisory Used: {'yes' if ai_review is not None and ai_review.schema_valid else 'no'}",
        f"Description: {cve.description or 'No description provided.'}",
    ]
    labels = tuple(
        label
        for label in (
            f"severity:{(cve.severity or 'unknown').lower()}",
            f"evidence:{evidence_label}",
            f"scope:{(product_scope or 'unknown').lower()}",
            *tuple(f"reason:{code}" for code in decision.reason_codes),
        )
        if label
    )
    metadata = {
        "cve_id": cve.cve_id,
        "severity": cve.severity,
        "canonical_name": canonical_name,
        "product_scope": product_scope,
        "poc_status": cve.poc_status.value,
        "poc_confidence": cve.poc_confidence,
        "itw_status": cve.itw_status.value,
        "itw_confidence": cve.itw_confidence,
        "policy_version": decision.policy_version,
        "policy_reason_codes": list(decision.reason_codes),
        "ai_review_used": bool(ai_review is not None and ai_review.schema_valid),
    }
    return PublishContent(
        schema_version=PUBLISH_CONTENT_SCHEMA_VERSION,
        title=title,
        summary=summary,
        body="\n".join(body_lines),
        labels=labels,
        metadata=metadata,
    )


def _derive_evidence_label(poc_status: EvidenceStatus, itw_status: EvidenceStatus) -> str:
    if itw_status is EvidenceStatus.PRESENT:
        return "itw"
    if poc_status is EvidenceStatus.PRESENT:
        return "poc"
    if itw_status is EvidenceStatus.ABSENT and poc_status is EvidenceStatus.ABSENT:
        return "none"
    return "unknown"


def _format_confidence(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"
