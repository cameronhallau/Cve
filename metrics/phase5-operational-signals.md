# Phase 5 Operational Signals

Phase 5 uses persisted counters in the `operational_metrics` table as the minimal observability baseline for update delivery and source-refresh hardening.

Current metric keys:

- `phase5.update_candidate.evaluations.total`
  - dimensions: `result`, `trigger`, optional `reason`
  - `result` values: `skipped`, `not_created`, `created`, `reused`
- `phase5.update_enqueue.attempts.total`
  - dimensions: `publication_event_type`, `result`, `target_name`, `trigger`
  - `result` values: `requested`, `reused`, `skipped`
- `phase5.update_publication.outcomes.total`
  - dimensions: `event_type`, `result`, `target_name`
  - `result` values: `succeeded`, `failed`, `duplicate_blocked`
- `phase5.stale_evidence.refresh.total`
  - dimensions: `action`, `signal_type`, `trigger`
- `phase5.ai_review.validation.total`
  - dimensions: `result`, `route_reason`
  - `result` values: `valid`, `invalid`

Operational notes:

- Counters are replay-safe at the event level because they are emitted from the same DB transaction paths that write the corresponding audit and publication state.
- `last_details` stores the latest deterministic payload for the dimension set so later dashboard or alert work can link counters back to concrete CVE, candidate, and publication identifiers.
- Phase 5 alert evaluation persists current alert status in `operational_alert_states` and transition history in `operational_alert_transitions` so active SLO and error-budget alerts remain replayable from stored state.
- These counters are a hardening baseline, not a dashboard implementation. Future UI or alerting work should read from `operational_metrics`, `operational_alert_states`, `operational_alert_transitions`, and `audit_events` rather than recreate event semantics in a second pipeline.
