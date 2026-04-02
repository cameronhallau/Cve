from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from cve_service.core.db import session_scope
from cve_service.models.entities import AIReview, CVE, Evidence, OperationalAlertState, OperationalAlertTransition, OperationalMetric, PublicationEvent
from cve_service.models.enums import CveState, EvidenceSignal, EvidenceSourceType, EvidenceStatus, PublicationEventStatus, PublicationEventType
from cve_service.services.ai_review import AIProviderResponse, execute_ai_review
from cve_service.services.alerting import (
    AI_SCHEMA_VALIDATION_METRIC_KEY,
    ALERT_STATUS_ACTIVE,
    ALERT_STATUS_RESOLVED,
    RULE_AI_SCHEMA_FAILURE,
    RULE_DUPLICATE_PUBLISH_GUARD,
    RULE_INGEST_FRESHNESS,
    RULE_SOURCE_ERROR_BUDGET,
    evaluate_operational_alerts,
    list_active_operational_alerts,
)
from cve_service.services.enrichment import EvidenceInput, record_evidence, refresh_stale_evidence
from cve_service.services.ingestion import PublicFeedRecord, ingest_public_feed_record
from cve_service.services.post_enrichment import process_post_enrichment_workflow
from cve_service.services.publication import publish_initial_publication
from cve_service.services.publish_targets import InMemoryPublishTarget


class NeverCalledProvider:
    def review(self, request):  # pragma: no cover - deterministic candidate never routes to AI
        raise AssertionError("AI should not be called for deterministic candidates")


class StaticAIProvider:
    def __init__(self, payload: dict[str, object] | str, *, model_name: str = "phase5-alert-test") -> None:
        self.payload = payload
        self.model_name = model_name

    def review(self, request) -> AIProviderResponse:
        return AIProviderResponse(
            model_name=self.model_name,
            payload=self.payload,
        )


def test_ingest_freshness_and_source_error_budget_alerts_persist_and_resolve(session_factory) -> None:
    evaluated_at = datetime(2026, 4, 3, 2, 0, tzinfo=UTC)

    with session_scope(session_factory) as session:
        _prepare_published_cve(session, "CVE-2026-5500", source_modified_at=datetime(2026, 4, 2, 10, 0, tzinfo=UTC))
        _prepare_published_cve(session, "CVE-2026-5501", source_modified_at=datetime(2026, 4, 2, 10, 5, tzinfo=UTC))
        for cve_id in ("CVE-2026-5500", "CVE-2026-5501"):
            cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
            evidence = session.scalar(
                select(Evidence)
                .where(Evidence.cve_id == cve.id, Evidence.signal_type == EvidenceSignal.POC)
                .order_by(Evidence.created_at.desc(), Evidence.id.desc())
            )
            evidence.collected_at = datetime(2026, 4, 2, 0, 0, tzinfo=UTC)
            evidence.freshness_ttl_seconds = 60

        refresh_stale_evidence(
            session,
            evaluated_at=evaluated_at,
        )
        evaluation = evaluate_operational_alerts(
            session,
            evaluated_at=evaluated_at,
            trigger="test.phase5.alerts.initial",
        )
        states = session.scalars(
            select(OperationalAlertState).order_by(OperationalAlertState.rule_key.asc(), OperationalAlertState.alert_key.asc())
        ).all()
        transitions = session.scalars(
            select(OperationalAlertTransition).order_by(
                OperationalAlertTransition.evaluated_at.asc(),
                OperationalAlertTransition.created_at.asc(),
                OperationalAlertTransition.id.asc(),
            )
        ).all()

    active_rule_keys = {state.rule_key for state in states if state.status == ALERT_STATUS_ACTIVE}
    transition_counts = {
        rule_key: len([transition for transition in transitions if transition.rule_key == rule_key])
        for rule_key in (RULE_INGEST_FRESHNESS, RULE_SOURCE_ERROR_BUDGET)
    }
    assert RULE_INGEST_FRESHNESS in active_rule_keys
    assert RULE_SOURCE_ERROR_BUDGET in active_rule_keys
    assert set(evaluation.active_alert_keys) == {state.alert_key for state in states if state.status == ALERT_STATUS_ACTIVE}
    assert transition_counts[RULE_INGEST_FRESHNESS] >= 1
    assert transition_counts[RULE_SOURCE_ERROR_BUDGET] >= 1

    with session_scope(session_factory) as session:
        replay = evaluate_operational_alerts(
            session,
            evaluated_at=evaluated_at,
            trigger="test.phase5.alerts.replay",
        )
        transitions = session.scalars(select(OperationalAlertTransition)).all()
        replay_transition_counts = {
            rule_key: len([transition for transition in transitions if transition.rule_key == rule_key])
            for rule_key in (RULE_INGEST_FRESHNESS, RULE_SOURCE_ERROR_BUDGET)
        }

    assert replay.activated_alert_keys == ()
    assert replay.resolved_alert_keys == ()
    assert replay_transition_counts == transition_counts

    with session_scope(session_factory) as session:
        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-5502",
                title="Exchange Server RCE",
                description="Freshness recovery fixture.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 3, 1, 45, tzinfo=UTC),
                vendor_name="Microsoft",
                product_name="Exchange Server",
            ),
        )
        freshness_resolved = evaluate_operational_alerts(
            session,
            evaluated_at=datetime(2026, 4, 3, 2, 0, tzinfo=UTC),
            trigger="test.phase5.alerts.resolve_freshness",
        )
        freshness_state = session.scalar(select(OperationalAlertState).where(OperationalAlertState.rule_key == RULE_INGEST_FRESHNESS))
        active_after_freshness = list_active_operational_alerts(session)

    assert RULE_INGEST_FRESHNESS not in {state.rule_key for state in active_after_freshness}
    assert {state.rule_key for state in active_after_freshness} == {RULE_SOURCE_ERROR_BUDGET}
    assert len(freshness_resolved.active_alert_keys) == 1
    assert freshness_state is not None
    assert freshness_state.status == ALERT_STATUS_RESOLVED

    with session_scope(session_factory) as session:
        ingest_public_feed_record(
            session,
            PublicFeedRecord(
                cve_id="CVE-2026-5503",
                title="Exchange Server RCE",
                description="Source budget recovery fixture.",
                severity="CRITICAL",
                source_name="fixture-feed",
                source_modified_at=datetime(2026, 4, 4, 2, 50, tzinfo=UTC),
                vendor_name="Microsoft",
                product_name="Exchange Server",
            ),
        )
        resolved = evaluate_operational_alerts(
            session,
            evaluated_at=evaluated_at + timedelta(hours=25),
            trigger="test.phase5.alerts.resolve_source_budget",
        )
        states = session.scalars(
            select(OperationalAlertState).order_by(OperationalAlertState.rule_key.asc(), OperationalAlertState.alert_key.asc())
        ).all()
        transitions = session.scalars(
            select(OperationalAlertTransition).order_by(
                OperationalAlertTransition.evaluated_at.asc(),
                OperationalAlertTransition.created_at.asc(),
                OperationalAlertTransition.id.asc(),
            )
        ).all()

    assert resolved.active_alert_keys == ()
    assert len(resolved.resolved_alert_keys) == 1
    assert {state.status for state in states} == {ALERT_STATUS_RESOLVED}
    assert len([transition for transition in transitions if transition.rule_key == RULE_INGEST_FRESHNESS]) >= 2
    assert len([transition for transition in transitions if transition.rule_key == RULE_SOURCE_ERROR_BUDGET]) >= 2


def test_ai_schema_validation_failure_spike_alert_uses_metrics_and_resolves(session_factory) -> None:
    requested_at = datetime(2026, 4, 3, 3, 0, tzinfo=UTC)

    with session_scope(session_factory) as session:
        for index, payload in enumerate(
            (
                "{",
                '{"cve_id":"CVE-2026-5601","enterprise_relevance_assessment":"enterprise_relevant"}',
                {
                    "cve_id": "CVE-2026-5602",
                    "enterprise_relevance_assessment": "enterprise_relevant",
                    "exploit_path_assessment": "internet_exploitable",
                    "confidence": 0.91,
                    "reasoning_summary": "Valid advisory payload.",
                },
            )
        ):
            cve_id = f"CVE-2026-560{index}"
            ingest_public_feed_record(session, _ambiguous_record(cve_id))
            record_evidence(session, _poc_evidence_input(cve_id, f"phase5-ai-{index}"))
            execute_ai_review(
                session,
                cve_id,
                StaticAIProvider(payload),
                requested_at=requested_at + timedelta(minutes=index * 5),
            )

        metric_rows = session.scalars(
            select(OperationalMetric).where(OperationalMetric.metric_key == AI_SCHEMA_VALIDATION_METRIC_KEY)
        ).all()
        active_alerts = list_active_operational_alerts(session)
        transitions = session.scalars(select(OperationalAlertTransition)).all()
        latest_review_created_at = session.scalar(select(AIReview.created_at).order_by(AIReview.created_at.desc()).limit(1))

    assert {metric.dimensions["result"] for metric in metric_rows} == {"invalid", "valid"}
    ai_alerts = [alert for alert in active_alerts if alert.rule_key == RULE_AI_SCHEMA_FAILURE]
    assert len(ai_alerts) == 1
    assert ai_alerts[0].current_payload["invalid_reviews"] == 2
    assert ai_alerts[0].current_payload["total_reviews"] == 3
    assert ai_alerts[0].current_payload["metric_totals"]
    assert len(transitions) == 1

    with session_scope(session_factory) as session:
        resolved = evaluate_operational_alerts(
            session,
            evaluated_at=latest_review_created_at + timedelta(hours=2),
            trigger="test.phase5.ai.resolve",
        )
        state = session.scalar(select(OperationalAlertState).where(OperationalAlertState.rule_key == RULE_AI_SCHEMA_FAILURE))
        transitions = session.scalars(
            select(OperationalAlertTransition).where(OperationalAlertTransition.rule_key == RULE_AI_SCHEMA_FAILURE)
        ).all()

    assert len(resolved.resolved_alert_keys) == 1
    assert state is not None
    assert state.status == ALERT_STATUS_RESOLVED
    assert len(transitions) == 2


def test_duplicate_publish_guard_alert_is_replayable_and_resolves(session_factory) -> None:
    with session_scope(session_factory) as session:
        initial_event = _prepare_published_cve(
            session,
            "CVE-2026-5700",
            source_modified_at=datetime(2026, 4, 3, 0, 0, tzinfo=UTC),
        )
        duplicate_event = PublicationEvent(
            cve_id=initial_event.cve_id,
            decision_id=initial_event.decision_id,
            policy_snapshot_id=initial_event.policy_snapshot_id,
            event_type=PublicationEventType.INITIAL,
            status=PublicationEventStatus.PUBLISHED,
            destination=initial_event.destination,
            idempotency_key=f"{initial_event.idempotency_key}-escaped",
            content_hash=initial_event.content_hash,
            external_id="escaped-duplicate",
            target_response={"duplicate": True},
            attempt_count=1,
            published_at=datetime(2026, 4, 3, 0, 10, tzinfo=UTC),
            last_attempted_at=datetime(2026, 4, 3, 0, 10, tzinfo=UTC),
            payload_snapshot=dict(initial_event.payload_snapshot),
            occurred_at=datetime(2026, 4, 3, 0, 10, tzinfo=UTC),
        )
        session.add(duplicate_event)
        session.flush()

        evaluation = evaluate_operational_alerts(
            session,
            evaluated_at=datetime(2026, 4, 3, 0, 15, tzinfo=UTC),
            trigger="test.phase5.duplicate.activate",
        )
        state = session.scalar(select(OperationalAlertState).where(OperationalAlertState.rule_key == RULE_DUPLICATE_PUBLISH_GUARD))
        transitions = session.scalars(
            select(OperationalAlertTransition).where(OperationalAlertTransition.rule_key == RULE_DUPLICATE_PUBLISH_GUARD)
        ).all()

    assert len(evaluation.active_alert_keys) == 1
    assert state is not None
    assert state.status == ALERT_STATUS_ACTIVE
    assert state.current_payload["duplicate_count"] == 2
    assert len(transitions) == 1

    with session_scope(session_factory) as session:
        duplicate_event = session.scalar(
            select(PublicationEvent).where(PublicationEvent.external_id == "escaped-duplicate")
        )
        duplicate_event.status = PublicationEventStatus.FAILED
        resolved = evaluate_operational_alerts(
            session,
            evaluated_at=datetime(2026, 4, 3, 0, 20, tzinfo=UTC),
            trigger="test.phase5.duplicate.resolve",
        )
        state = session.scalar(select(OperationalAlertState).where(OperationalAlertState.rule_key == RULE_DUPLICATE_PUBLISH_GUARD))
        transitions = session.scalars(
            select(OperationalAlertTransition).where(OperationalAlertTransition.rule_key == RULE_DUPLICATE_PUBLISH_GUARD)
        ).all()

    assert len(resolved.resolved_alert_keys) == 1
    assert state is not None
    assert state.status == ALERT_STATUS_RESOLVED
    assert len(transitions) == 2


def _prepare_published_cve(
    session,
    cve_id: str,
    *,
    source_modified_at: datetime,
) -> PublicationEvent:
    ingest_public_feed_record(
        session,
        PublicFeedRecord(
            cve_id=cve_id,
            title="Exchange Server RCE",
            description="Phase 5 alerting fixture.",
            severity="CRITICAL",
            source_name="fixture-feed",
            source_modified_at=source_modified_at,
            vendor_name="Microsoft",
            product_name="Exchange Server",
        ),
    )
    record_evidence(
        session,
        EvidenceInput(
            cve_id=cve_id,
            signal_type=EvidenceSignal.POC,
            status=EvidenceStatus.PRESENT,
            source_name="trusted-poc-db",
            source_type=EvidenceSourceType.TRUSTED_POC,
            source_record_id=f"alert-poc-{cve_id.lower()}",
            evidence_timestamp=source_modified_at + timedelta(minutes=10),
            collected_at=source_modified_at + timedelta(minutes=10),
            freshness_ttl_seconds=14 * 24 * 60 * 60,
            confidence=0.94,
            raw_payload={"origin": "phase5-alerting"},
        ),
    )
    workflow_result = process_post_enrichment_workflow(
        session,
        cve_id,
        NeverCalledProvider(),
        requested_at=source_modified_at + timedelta(minutes=11),
        evaluated_at=source_modified_at + timedelta(minutes=11),
    )
    assert workflow_result.state is CveState.PUBLISH_PENDING
    publish_initial_publication(
        session,
        cve_id,
        InMemoryPublishTarget(name=f"phase5-alert-initial-{cve_id.lower()}"),
        attempted_at=source_modified_at + timedelta(minutes=12),
    )
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id))
    publication_event = session.scalar(
        select(PublicationEvent)
        .where(PublicationEvent.cve_id == cve.id, PublicationEvent.event_type == PublicationEventType.INITIAL)
        .order_by(PublicationEvent.published_at.desc(), PublicationEvent.id.desc())
    )
    assert publication_event is not None
    return publication_event


def _ambiguous_record(cve_id: str) -> PublicFeedRecord:
    return PublicFeedRecord(
        cve_id=cve_id,
        title="Widget Gateway issue",
        description="High severity issue in an ambiguous gateway line.",
        severity="HIGH",
        source_name="fixture-feed",
        source_modified_at=datetime(2026, 4, 3, 2, 0, tzinfo=UTC),
        vendor_name="Acme",
        product_name="Widget Gateway",
    )


def _poc_evidence_input(cve_id: str, source_record_id: str) -> EvidenceInput:
    return EvidenceInput(
        cve_id=cve_id,
        signal_type=EvidenceSignal.POC,
        status=EvidenceStatus.PRESENT,
        source_name="trusted-poc-db",
        source_record_id=source_record_id,
        evidence_timestamp=datetime(2026, 4, 3, 2, 10, tzinfo=UTC),
        collected_at=datetime(2026, 4, 3, 2, 10, tzinfo=UTC),
        freshness_ttl_seconds=14 * 24 * 60 * 60,
        confidence=0.9,
        raw_payload={"origin": "phase5-ai-alert"},
    )
