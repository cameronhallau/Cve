# ADR 0001: Rules-First Policy

## Status

Accepted

## Context

The system must prioritize deterministic publish and suppress rules so that core policy remains explainable, testable, and replayable.

## Decision

Deterministic classification runs before enrichment-driven AI routing and before any publish policy resolution. Hard deny outcomes from deterministic rules cannot be bypassed downstream.

## Consequences

- rule execution becomes a required precursor to later phases
- AI cost and ambiguity are constrained to narrower cases
- regression replay remains stable for unchanged rule and policy versions
