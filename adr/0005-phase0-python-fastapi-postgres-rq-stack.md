# ADR 0005: Phase 0 Runtime Stack

## Status

Accepted

## Context

Phase 0 needs the smallest runnable service skeleton that satisfies the execution baseline in [BUILD.md](/home/cam/Documents/Github/Vuln/Cve/BUILD.md): API bootstrap, persistent state, queue wiring, migrations, and testable health checks. The baseline also requires audit-friendly persistence, rules-first decisioning, fail-closed behavior, and clean separation of PoC and ITW concepts.

## Decision

Phase 0 uses:

- Python 3.12 for the service runtime
- FastAPI for the HTTP API
- PostgreSQL for persistent state
- SQLAlchemy 2.x ORM for the domain model
- Alembic for schema migration control
- Redis plus RQ for background job execution
- Pydantic v2 for settings and API/data models
- pytest for the Phase 0 exit-gate tests
- Docker Compose for local Postgres and Redis wiring

## Consequences

- the API and worker share the same typed settings and infrastructure helpers
- migrations remain explicit and reviewable instead of inferred at runtime
- local development stays small by composing only the two backing services required for Phase 0
- the queue framework is ready for later ingestion and policy jobs without pulling Phase 1 logic forward
- schema design can preserve audit trails and PoC versus ITW separation from the first migration

