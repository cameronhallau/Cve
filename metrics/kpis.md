# KPIs

Track these KPIs from the first executable build onward:

- publish precision over a rolling window
- suppress-to-publish ratio by source cohort
- AI route rate for incoming eligible CVEs
- duplicate publish prevention rate
- mean ingest-to-decision latency
- mean decision-to-publish latency
- material-change update rate for previously published CVEs
- audit trace completeness rate

Interpretation notes:

- publish precision is the primary quality KPI and starts with a target of at least 85 percent
- AI route rate should decrease as deterministic coverage improves
- audit trace completeness must remain at 100 percent
