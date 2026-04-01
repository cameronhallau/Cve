# ADR 0003: Fail Closed and Preserve Auditability

## Status

Accepted

## Context

The system must be safe by default and must support post-hoc reconstruction of any decision.

## Decision

Unknown, low-confidence, conflicting, or invalid states fail closed to suppression or deferred refresh. Every material decision point writes an immutable audit event with the inputs, rule versions, policy versions, and outcome.

## Consequences

- incomplete evidence never silently upgrades a CVE to publishable
- audit logging is part of the happy path rather than an afterthought
- replay and regression tooling depend on persisted state rather than inferred history
