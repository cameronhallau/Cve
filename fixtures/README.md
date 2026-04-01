# Fixtures

This directory holds the scenario corpus used for E2E, regression replay, and decision-trace validation.

- [mandatory-scenarios.yaml](/home/cam/Documents/Github/Vuln/Cve/fixtures/mandatory-scenarios.yaml)

Fixture guidance:

- keep each scenario deterministic and named by expected outcome
- include enough source and evidence detail to replay policy decisions
- capture both initial publish paths and later update-triggering deltas
