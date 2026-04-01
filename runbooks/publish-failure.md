# Publish Failure Runbook

## Trigger

Use this runbook when initial publish or update publish attempts fail, retry loops spike, or duplicate-post protection is suspected to be broken.

## Immediate Actions

1. Confirm whether the failure happened before or after the external post was accepted.
2. Inspect publish state, content hash, and external reference IDs.
3. Pause retries if idempotency cannot be proven.
4. Preserve all related decision and publication events for audit.

## Recovery

1. If the external post definitely did not occur, resume retry with the existing idempotency key.
2. If the external post may have occurred, reconcile against the downstream platform before retrying.
3. If duplicate prevention failed, suppress further retries and create a corrective update task.
4. Record the final disposition, including whether the incident affected initial publication, update publication, or both.
