# SLOs and Alerts

## Initial SLOs

- ingestion freshness: new source data processed within agreed freshness window
- decision trace completeness: 100 percent of decisions produce required audit records
- publish idempotency: 100 percent duplicate prevention for retried publish attempts
- mandatory scenario pass rate: 100 percent in CI for the fixed scenario set

## Alert Conditions

- ingest lag exceeds 6 hours for the latest processed snapshot of a source
- live poll cursor stalls or repeated poll failures require investigation through `source_progress`, `phase6.ingest_poll.runs.total`, and the source audit trail
- audit completeness drops below 100 percent
- duplicate publish guard records any escaped duplicate
- AI schema validation failures spike above normal baseline
  - active when at least 2 AI reviews in the last hour are schema-invalid and invalid reviews are at least 50 percent of recent AI attempts
- source failure rates breach error budget
  - active when stale-refresh reevaluation affects at least 2 CVEs for the same source within 24 hours

## Operational Principle

Alerts should point to a specific broken contract, not just a noisy symptom. Every alert should map back to one of the build gates or non-negotiable quality bars in [BUILD.md](/home/cam/Documents/Github/Vuln/Cve/BUILD.md).

Scheduled alert evaluation is part of the production contract:

- run `cve-alert-eval-once` on a fixed cadence so stored metrics and audit state materialize into replayable alert state
- run alert evaluation after major recovery actions such as poll repair, stale-refresh replay, or X reconciliation
- treat `source_progress.last_successful_poll_at`, `source_progress.last_seen_upstream_fetch_at`, and persisted ingest-poll metrics as first-class alert inputs even when a dedicated cursor-stall rule has not yet been added
