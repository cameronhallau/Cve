# ADR 0002: Preserve PoC and ITW as Separate Signals

## Status

Accepted

## Context

Proof-of-concept availability and in-the-wild exploitation are related but materially different signals with different operational meanings.

## Decision

The system stores and computes PoC and ITW evidence independently, each with its own source set, freshness, confidence, and summary fields.

## Consequences

- enrichment models need distinct status and confidence fields
- update detection can trigger on one signal changing without the other
- downstream policy can reason about PoC and ITW separately instead of collapsing evidence quality
