# ADR 0004: AI Is Advisory Only

## Status

Accepted

## Context

AI is useful for borderline enterprise relevance and exploitability interpretation, but it introduces probabilistic behavior and schema failure risks.

## Decision

AI responses are accepted only after schema validation and are treated as advisory signals. AI may inform enterprise relevance and exploit path assessment, but it cannot override hard deterministic denies or create publish outcomes without a passing policy gate.

## Consequences

- strict AI I/O schemas are required
- invalid responses stop state progression
- policy resolution must explicitly log deterministic and AI conflicts
