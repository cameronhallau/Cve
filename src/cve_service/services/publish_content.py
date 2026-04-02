from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cve_service.models.entities import AIReview, CVE, Classification, PolicyDecision, UpdateCandidate
from cve_service.models.enums import EvidenceStatus

PUBLISH_CONTENT_SCHEMA_VERSION = "phase4-initial-publication.v1"
UPDATE_PUBLISH_CONTENT_SCHEMA_VERSION = "phase5-update-publication.v1"


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


def build_update_publish_content(
    *,
    update_candidate: UpdateCandidate,
) -> PublishContent:
    snapshot = update_candidate.comparison_snapshot or {}
    baseline = snapshot.get("baseline", {})
    current = snapshot.get("current", {})
    material_changes = list((snapshot.get("changes") or {}).get("material", []))
    current_cve = current.get("cve", {})
    baseline_cve = baseline.get("cve", {})
    current_classification = current.get("classification", {})
    reason_codes = list(snapshot.get("reason_codes") or update_candidate.reason_codes)
    cve_id = current_cve.get("cve_id") or baseline_cve.get("cve_id") or "unknown-cve"
    severity = current_cve.get("severity") or baseline_cve.get("severity") or "UNKNOWN"
    canonical_name = current_classification.get("canonical_name") or "unknown-product"
    product_scope = current_classification.get("product_scope") or "unknown"
    title = f"{cve_id} Update: {_summarize_material_changes(material_changes)}"
    summary = " | ".join(
        part
        for part in (
            severity,
            canonical_name,
            _summarize_signal_changes(material_changes),
        )
        if part
    )
    body_lines = [
        f"CVE: {cve_id}",
        f"Severity: {severity}",
        f"Product: {canonical_name}",
        f"Product Scope: {product_scope}",
        f"Baseline Publication Event: {(baseline.get('publication') or {}).get('event_id') or 'unknown'}",
        f"Update Candidate: {update_candidate.id}",
        f"Comparison Fingerprint: {update_candidate.comparison_fingerprint}",
        f"Reason Codes: {', '.join(reason_codes) if reason_codes else 'none'}",
        "Material Changes:",
        *[
            f"- {change.get('field', 'unknown')}: {change.get('before')} -> {change.get('after')} ({change.get('explanation', 'No explanation recorded.')})"
            for change in material_changes
        ],
        (
            "Baseline Evidence: "
            f"PoC={_format_snapshot_signal(baseline, 'poc')}, "
            f"ITW={_format_snapshot_signal(baseline, 'itw')}"
        ),
        (
            "Current Evidence: "
            f"PoC={_format_snapshot_signal(current, 'poc')}, "
            f"ITW={_format_snapshot_signal(current, 'itw')}"
        ),
    ]
    labels = tuple(
        label
        for label in (
            "publication:update",
            f"severity:{str(severity).lower()}",
            f"scope:{str(product_scope).lower()}",
            *tuple(f"reason:{code}" for code in reason_codes),
            *tuple(f"signal:{_signal_label(change.get('field'))}" for change in material_changes),
        )
        if label
    )
    metadata = {
        "cve_id": cve_id,
        "severity": severity,
        "canonical_name": canonical_name,
        "product_scope": product_scope,
        "update_candidate_id": str(update_candidate.id),
        "comparison_fingerprint": update_candidate.comparison_fingerprint,
        "comparator_version": update_candidate.comparator_version,
        "baseline_publication_event_id": (baseline.get("publication") or {}).get("event_id"),
        "reason_codes": reason_codes,
        "material_changes": material_changes,
        "baseline_evidence": baseline.get("evidence", {}),
        "current_evidence": current.get("evidence", {}),
    }
    return PublishContent(
        schema_version=UPDATE_PUBLISH_CONTENT_SCHEMA_VERSION,
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


def _format_snapshot_signal(snapshot: dict[str, Any], signal_name: str) -> str:
    signal = (snapshot.get("evidence") or {}).get(signal_name, {})
    return f"{signal.get('status', 'UNKNOWN')} ({_format_confidence(signal.get('confidence'))})"


def _summarize_material_changes(material_changes: list[dict[str, Any]]) -> str:
    if not material_changes:
        return "No material changes recorded"
    if len(material_changes) == 1:
        change = material_changes[0]
        field = _signal_label(change.get("field"))
        return f"{field.upper()} {change.get('before')} -> {change.get('after')}"
    return f"{len(material_changes)} material changes"


def _summarize_signal_changes(material_changes: list[dict[str, Any]]) -> str:
    if not material_changes:
        return "no-material-change"
    return ", ".join(
        f"{_signal_label(change.get('field'))}:{change.get('before')}->{change.get('after')}"
        for change in material_changes
    )


def _signal_label(field_name: Any) -> str:
    if not isinstance(field_name, str):
        return "unknown"
    if field_name == "evidence.poc_status":
        return "poc"
    if field_name == "evidence.itw_status":
        return "itw"
    return field_name.rsplit(".", 1)[-1]
