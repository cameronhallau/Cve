# CVE Intelligence Bot Mk2 Build Baseline

This document is the execution baseline for building the CVE Intelligence Bot Mk2. It converts the product direction into build phases, quality gates, artifact expectations, and agent handoff rules.

## Product Intent

Build a standalone, stateful CVE intelligence system that publishes only enterprise-relevant High or Critical CVEs using rules-first decisioning, evidence enrichment, selective AI, and update-aware publishing with no human-in-the-loop requirement.

## Core Workflow

1. Ingest new or updated CVEs.
2. Normalize product and vendor names.
3. Run deterministic rules and reason codes.
4. Enrich with PoC and ITW evidence.
5. Route only ambiguous cases to AI.
6. Apply autonomous publish policy with AI as advisory only.
7. Publish once or suppress.
8. Re-check published CVEs for material changes and issue updates.
9. Log every decision for audit and replay.

## Non-Negotiables

- Rules-first, AI-second.
- PoC and ITW remain separate signals.
- Every decision must be reconstructable from stored state.
- Unknown or low-confidence outcomes fail closed to suppress or defer.
- AI cannot override hard policy denies.

## Build Phases

### Phase 0: Foundation and Skeleton

Goal: establish the runnable service skeleton, persistence model, queue framework, and state machine primitives.

Deliverables:

- project scaffold for API, workers, config, and migrations
- core tables for CVEs, products, classifications, evidence, AI reviews, policy decisions, publication events, and audit events
- state machine enums and transition guard helpers

Exit gate:

- migrations apply and roll back cleanly
- worker processes a no-op queue job
- API health endpoints report DB and queue connectivity

### Phase 1: Ingestion, Normalization, and Deterministic Classification

Goal: convert raw CVE records into deterministic candidate outcomes with versioned reason codes.

Deliverables:

- source adapters for initial public feeds
- idempotent dedup and upsert by CVE ID with snapshot retention
- product canonicalization and alias matching
- deterministic classifier with rule versioning and reason code trace

Exit gate:

- re-ingest of the same CVE is idempotent
- classifier runs before any AI route
- consumer-only products are denied by rule
- every candidate stores classifier version and reason codes

### Phase 2: Enrichment and Evidence Model

Goal: add exploitability evidence and compute PoC and ITW summaries with confidence.

Deliverables:

- evidence collectors for vendor advisories, trusted PoC sources, known-exploited feeds, and research references
- evidence storage with freshness and confidence
- enrichment summary model with `poc_status`, `itw_status`, and confidence fields

Exit gate:

- PoC and ITW are independently computed and stored
- source quality affects confidence
- stale evidence refresh works without incorrect duplication

### Phase 3: AI Review and Policy Gating

Goal: route only ambiguous cases to AI and enforce strictly validated structured outputs.

Deliverables:

- AI review input pack builder
- strict JSON schema validation for AI responses
- policy gate that combines deterministic outputs, evidence, and AI advisory signals

Exit gate:

- non-ambiguous deterministic cases skip AI
- invalid AI JSON cannot progress candidate state
- AI cannot override hard deny rules
- AI assessments remain advisory only

### Phase 4: Autonomous Policy and Publish Pipeline

Goal: enforce autonomous decision policy and a safe, idempotent publication lifecycle.

Deliverables:

- autonomous policy resolver for deterministic and AI conflicts
- durable, versioned policy configuration capture
- publish worker with duplicate prevention and retry-safe posting

Exit gate:

- conflict resolution events store policy version, reason, and outcome
- duplicate initial publish is blocked by state and content hash checks
- failed publish retries remain idempotent

### Phase 5: Update Detection and Hardening

Goal: detect material changes, issue updates, and harden the system operationally.

Deliverables:

- material-change comparator for published CVEs
- update reply workflow for PoC, ITW, and authoritative exploit deltas
- dashboards, metrics, and source failure observability

Exit gate:

- non-material metadata churn does not trigger updates
- material evidence changes create update candidates
- SLO and error budget alerts are active

## Cross-Phase Quality Gates

Required test layers:

- unit tests for rule, parser, scorer, and policy logic
- integration tests for DB, queue, worker, and API behavior
- end-to-end tests for the synthetic lifecycle scenarios
- regression replay for a fixed CVE corpus
- security checks for authn, authz, secret handling, and audit immutability

Mandatory scenarios:

1. High or Critical unauthenticated RCE with trusted PoC publishes.
2. Critical consumer router CVE suppresses.
3. High enterprise product with unknown relevance routes through AI and policy.
4. Previously published CVE gains KEV or ITW evidence and triggers update flow.
5. Duplicate ingestion and duplicate publish attempts still produce one publish event.
6. AI says publishable but deterministic consumer-only deny still suppresses.

Release thresholds:

- unit tests at or above 90 percent pass rate
- integration tests at 100 percent for critical paths
- E2E mandatory scenarios at 100 percent
- decision trace completeness at 100 percent
- rolling publish precision target at or above 85 percent

## Context-Managed Execution Method

Every build cycle must carry a compact context package:

- `objective`
- `task_scope`
- `constraints`
- `inputs`
- `outputs_expected`
- `acceptance_checks`
- `open_risks`

Execution protocol:

1. Confirm phase and gate target.
2. State assumptions and failure mode.
3. Implement the smallest viable increment.
4. Run the required test subset.
5. Record artifacts and reasoned outcome.
6. If a gate fails, create the next fix task immediately.

Agent handoff template:

```yaml
phase: "Phase 2"
task: "Implement enrichment_summary aggregation"
changed_artifacts:
  - "app/services/enrichment.py"
  - "app/models/enrichment_summary.py"
  - "tests/integration/test_enrichment_summary.py"
decisions:
  - "poc_status computed independently from itw_status"
  - "source_quality weighted 0.2-1.0"
checks_run:
  - "pytest tests/integration/test_enrichment_summary.py"
result:
  status: "pass"
open_risks:
  - "KEV feed adapter retry tuning pending"
next_step: "Add stale-evidence refresh worker"
```

## Required Artifact Set

- [architecture/README.md](/home/cam/Documents/Github/Vuln/Cve/architecture/README.md)
- [adr/README.md](/home/cam/Documents/Github/Vuln/Cve/adr/README.md)
- [schemas/README.md](/home/cam/Documents/Github/Vuln/Cve/schemas/README.md)
- [fixtures/README.md](/home/cam/Documents/Github/Vuln/Cve/fixtures/README.md)
- [runbooks/README.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/README.md)
- [metrics/README.md](/home/cam/Documents/Github/Vuln/Cve/metrics/README.md)

## Immediate Backlog

1. Create schema and migrations for core tables and audit events.
2. Implement deterministic classifier v1 and the reason code registry.
3. Add ingestion dedup and snapshot compare logic.
4. Build enrichment summary computation with PoC and ITW separation.
5. Implement AI review schema validation and hard policy guardrails.
6. Add publish idempotency and duplicate suppression checks.
7. Add the mandatory E2E scenario suite and regression corpus replay.

## Definition of Done

The system is done only when:

1. The end-to-end pipeline runs from ingestion through publish and update simulation.
2. All phase gates pass.
3. The audit trail explains publish, suppress, and escalate decisions.
4. Replay of prior CVE state yields deterministic outcomes for the same rule version.
5. Low-confidence or conflicting outcomes fail closed to suppression or deferred refresh.
