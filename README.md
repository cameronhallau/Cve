# CVE Intelligence Bot Mk2

This repository contains the build and operational documentation base for the CVE Intelligence Bot Mk2.

The current implementation baseline lives in [BUILD.md](/home/cam/Documents/Github/Vuln/Cve/BUILD.md). Supporting artifacts are organized to match the required maintainability set from that baseline:

- [architecture/README.md](/home/cam/Documents/Github/Vuln/Cve/architecture/README.md)
- [adr/README.md](/home/cam/Documents/Github/Vuln/Cve/adr/README.md)
- [schemas/README.md](/home/cam/Documents/Github/Vuln/Cve/schemas/README.md)
- [fixtures/README.md](/home/cam/Documents/Github/Vuln/Cve/fixtures/README.md)
- [runbooks/README.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/README.md)
- [metrics/README.md](/home/cam/Documents/Github/Vuln/Cve/metrics/README.md)

Initial documentation priorities:

1. Keep rules-first decisioning explicit.
2. Preserve PoC and ITW as independent evidence signals.
3. Make every publish or suppress decision reconstructable.
4. Fail closed when confidence or evidence quality is insufficient.
