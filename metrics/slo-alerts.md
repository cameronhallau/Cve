# SLOs and Alerts

## Initial SLOs

- ingestion freshness: new source data processed within agreed freshness window
- decision trace completeness: 100 percent of decisions produce required audit records
- publish idempotency: 100 percent duplicate prevention for retried publish attempts
- mandatory scenario pass rate: 100 percent in CI for the fixed scenario set

## Alert Conditions

- ingest lag exceeds freshness target
- audit completeness drops below 100 percent
- duplicate publish guard records any escaped duplicate
- AI schema validation failures spike above normal baseline
- source failure rates breach error budget

## Operational Principle

Alerts should point to a specific broken contract, not just a noisy symptom. Every alert should map back to one of the build gates or non-negotiable quality bars in [BUILD.md](/home/cam/Documents/Github/Vuln/Cve/BUILD.md).
