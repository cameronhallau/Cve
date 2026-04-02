# Publish Failure Runbook

## Trigger

Use this runbook when initial publish or update publish attempts fail, retry loops spike, or duplicate-post protection is suspected to be broken.

## Immediate Actions

1. Confirm whether the failure happened before or after the external post was accepted.
2. Inspect publish state, content hash, and external reference IDs.
3. Pause retries if idempotency cannot be proven.
4. Preserve all related decision and publication events for audit.

## Scheduled Runtime Checks

- confirm whether the failure came from:
  - continuous `cve-worker` processing
  - a scheduled stale-refresh rerun that enqueued an update
  - a previously queued publish attempt replayed after worker recovery
- keep scheduled ingest, stale-refresh, and alert-evaluation timers running unless they are the fault domain
- do not blindly rerun publish work from cron or systemd:
  - the worker already owns publish retries
  - scheduled refresh jobs may enqueue new work with the same safety checks
  - reconciliation-required failures must stay fail-closed until the remote state is known

## X Target Checks

When the publish target is `x`, inspect the publication event `target_response` and `payload_snapshot` before doing anything else.

1. Confirm `failure_category`, `retryable`, `rate_limited`, and `requires_reconciliation`.
2. If `requires_reconciliation=true`, do not rerun the publication job until the remote thread is reconciled.
3. Compare the stored `external_id`, `root_post_id`, `post_ids`, and any `partial_post_ids` against the live X account history.
4. If the failed event was an update publish, verify that the baseline publication event still carries the correct X `external_id` for reply threading.
5. Check the most recent X rate-limit headers and `retry_after_seconds` before scheduling any retry.

## Recovery

1. If the external post definitely did not occur, resume retry with the existing idempotency key.
2. If the external post may have occurred, reconcile against the downstream platform before retrying.
3. If duplicate prevention failed, suppress further retries and create a corrective update task.
4. Record the final disposition, including whether the incident affected initial publication, update publication, or both.

## Autonomous Runtime Notes

- reconciliation-required X failures are expected to block autonomous progress for that publication event
- operators must repair or supersede the failed event rather than enqueueing a fresh publish blindly
- once reconciliation is complete, allow the worker to resume with the existing event lineage and idempotency material
- if the failure occurred during an update publish, verify that later scheduled stale-refresh runs do not create competing update candidates before the blocked event is resolved

## Credential Expectations

- `CVE_PUBLISH_TARGET_NAME=x` is opt-in and should only be enabled after credentials are present.
- Supported auth modes:
  - `oauth1_user`: `CVE_X_CONSUMER_KEY`, `CVE_X_CONSUMER_SECRET`, `CVE_X_ACCESS_TOKEN`, `CVE_X_ACCESS_TOKEN_SECRET`
  - `oauth2_bearer`: `CVE_X_BEARER_TOKEN`
- Startup fails fast when X mode is enabled but the required credentials are missing.
- Do not place secrets in code, fixtures, or committed config files. Use environment injection only.
