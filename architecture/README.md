# Architecture

This directory holds the system-level design views used to guide implementation.

- [system-overview.md](/home/cam/Documents/Github/Vuln/Cve/architecture/system-overview.md) describes the primary components and data flow.

Architecture guidance:

- prefer evented workers around a durable state store
- keep policy resolution separate from ingestion and enrichment
- make replay and audit access first-class concerns
