# Phase 6 Live Ingestion Signals

Phase 6 adds durable live-ingestion runtime state for unattended source polling and scheduled operations.

Current additions:

- `source_progress`
  - one durable row per live source
  - stores the last successful cursor, last successful poll time, latest seen upstream fetch time, consecutive failures, and the most recent deterministic error payload
- `phase6.ingest_poll.runs.total`
  - dimensions: `failure_stage`, `result`, `source_name`
  - `result` values: `succeeded`, `noop`, `failed`
  - `failure_stage` is `none` for success and no-op runs

Operational notes:

- The live ingest poller advances `source_progress.cursor` only after a successful run. Failed runs leave the cursor unchanged so scheduled reruns remain replay-safe.
- `last_run_details` on `source_progress` captures the deterministic summary for the last run, including checkpoint movement, record counts, and any failure stage/message.
- Source-level poll events are also written to `audit_events` with `entity_type=source_progress` so operators can correlate cursor movement and failures without requiring a dashboard.
- Alert evaluation continues to read from persisted metrics and audit state after each poll, refresh, or explicit alert-evaluation run.
