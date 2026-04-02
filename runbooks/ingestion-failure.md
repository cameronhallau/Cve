# Ingestion Failure Runbook

## Trigger

Use this runbook when source adapters fail repeatedly, ingestion lag breaches SLO, or snapshot parsing errors start accumulating.

## Immediate Actions

1. Confirm which source or parser is failing.
2. Check queue backlog, retry counts, `source_progress.last_successful_poll_at`, and `source_progress.consecutive_failures`.
3. Validate whether the failure is source-side, parser-side, or persistence-side.
4. Fail closed by suppressing stale downstream decisions rather than publishing from incomplete inputs.

## Live Poll Checks

- inspect `source_progress` for `source_name='cve.org'`
- confirm:
  - `cursor.last_successful_fetch_time`
  - `last_run_status`
  - `last_seen_upstream_fetch_at`
  - `consecutive_failures`
  - `last_error.stage`
- distinguish:
  - `NOOP`: the poll reached the upstream feed and found no new delta entries beyond the stored cursor
  - `FAILED`: the poll did not complete the current delta window and the cursor must not be assumed to have advanced
- review source audit events:
  - `ingestion.poll_started`
  - `ingestion.poll_succeeded`
  - `ingestion.poll_no_change`
  - `ingestion.poll_failed`

## Required Evidence

- failing source name and timestamp
- `source_progress.cursor`, `last_run_status`, and `last_error`
- affected adapter version
- sample error payload or parser exception
- number of queued and delayed jobs
- `source_progress.last_run_details`
- latest `phase6.ingest_poll.runs.total` metric payload for the affected source

## Recovery

1. Disable or rate-limit the failing source adapter if it is producing malformed or hostile data.
2. Re-run ingestion against a captured sample before restoring the source.
3. Rerun `cve-ingest-poll-once` after the source path is stable. The cursor should stay unchanged across failures and advance only on the first successful rerun.
4. Replay queued CVEs once the adapter and parser path are stable.
5. Verify `audit_events`, `operational_metrics`, and `source_progress` all reflect the failure interval and recovery run.

## Cursor Recovery

1. Confirm whether the failed poll committed any CVE snapshots before the error.
2. Do not advance or rewrite `source_progress.cursor` manually unless the skipped upstream window is independently reconciled.
3. Repair the source-side problem first:
   - `delta_log_fetch` or `record_fetch`: network, host allowlist, GitHub/raw access, timeout, or upstream availability
   - `delta_log_parse` or `record_parse`: malformed JSON or unexpected feed shape
   - `record_adapt`: CVE JSON content no longer matches the expected public-feed adaptation rules
4. Rerun `.venv/bin/cve-ingest-poll-once`.
5. Confirm the rerun either:
   - advances `cursor.last_successful_fetch_time`, or
   - returns `NOOP` with a stable cursor and a later `last_seen_upstream_fetch_at`

## Replay Notes

- Re-running `cve-ingest-poll-once` is safe:
  - source checkpoint advancement is durable
  - ingestion snapshot creation is idempotent on payload hash
  - post-enrichment queue handoff is deduplicated by job fingerprint
- No-op polls should not create duplicate CVE snapshots or classifications.
- Failed polls should leave the durable cursor at the last known good fetch time.

## Escalation

- If `last_seen_upstream_fetch_at` keeps moving but the cursor does not, treat it as a cursor stall and investigate immediately.
- If ingest freshness alerting remains active after a successful rerun, inspect the latest stored snapshot timestamps and scheduled timer health.
- If parser failures repeat on valid upstream records, capture the raw payload and open a deterministic adapter fix before restoring unattended polling.
