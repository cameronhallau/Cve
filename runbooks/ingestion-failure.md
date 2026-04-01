# Ingestion Failure Runbook

## Trigger

Use this runbook when source adapters fail repeatedly, ingestion lag breaches SLO, or snapshot parsing errors start accumulating.

## Immediate Actions

1. Confirm which source or parser is failing.
2. Check queue backlog, retry counts, and last successful ingest time.
3. Validate whether the failure is source-side, parser-side, or persistence-side.
4. Fail closed by suppressing stale downstream decisions rather than publishing from incomplete inputs.

## Required Evidence

- failing source name and timestamp
- affected adapter version
- sample error payload or parser exception
- number of queued and delayed jobs

## Recovery

1. Disable or rate-limit the failing source adapter if it is producing malformed or hostile data.
2. Re-run ingestion against a captured sample before restoring the source.
3. Replay queued CVEs once the adapter and parser path are stable.
4. Verify audit events exist for the failure interval and replay actions.
