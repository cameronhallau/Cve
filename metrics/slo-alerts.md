# SLOs and Alerts

## Initial SLOs

- ingestion freshness: new source data processed within agreed freshness window
- decision trace completeness: 100 percent of decisions produce required audit records
- publish idempotency: 100 percent duplicate prevention for retried publish attempts
- mandatory scenario pass rate: 100 percent in CI for the fixed scenario set

## Alert Conditions

- ingest lag exceeds 6 hours for the latest processed snapshot of a source
- audit completeness drops below 100 percent
- duplicate publish guard records any escaped duplicate
- AI schema validation failures spike above normal baseline
  - active when at least 2 AI reviews in the last hour are schema-invalid and invalid reviews are at least 50 percent of recent AI attempts
- source failure rates breach error budget
  - active when stale-refresh reevaluation affects at least 2 CVEs for the same source within 24 hours

## Operational Principle

Alerts should point to a specific broken contract, not just a noisy symptom. Every alert should map back to one of the build gates or non-negotiable quality bars in [BUILD.md](/home/cam/Documents/Github/Vuln/Cve/BUILD.md).
