# CVE Intelligence Bot Mk2

This repository contains the build and operational documentation base and the Phase 0 service skeleton for the CVE Intelligence Bot Mk2.

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

## Local Setup

The current implementation is the Phase 0 foundation on the Python, FastAPI, PostgreSQL, Redis, and RQ stack documented in [adr/0005-phase0-python-fastapi-postgres-rq-stack.md](/home/cam/Documents/Github/Vuln/Cve/adr/0005-phase0-python-fastapi-postgres-rq-stack.md).

### Local Services

- PostgreSQL: `localhost:55432`
- Redis queue: `localhost:56379`

Environment defaults live in [.env.example](/home/cam/Documents/Github/Vuln/Cve/.env.example).

### Publish Target Selection

The publish path stays opt-in and defaults to `console`.

- Set `CVE_PUBLISH_TARGET_NAME=x` to enable the real X target.
- When `x` is enabled, startup fails fast unless one complete auth mode is configured.
- For unattended production, prefer `CVE_X_AUTH_MODE=oauth1_user` unless the deployment has already proven a durable OAuth 2 user-token lifecycle outside this service.
- Supported auth modes:
  - `CVE_X_AUTH_MODE=oauth1_user` with `CVE_X_CONSUMER_KEY`, `CVE_X_CONSUMER_SECRET`, `CVE_X_ACCESS_TOKEN`, and `CVE_X_ACCESS_TOKEN_SECRET`
  - `CVE_X_AUTH_MODE=oauth2_bearer` with `CVE_X_BEARER_TOKEN`
- The X target is isolated behind the existing publish target abstraction, so `console`, `inline`, and in-memory test targets continue to work unchanged.
- Update publications on X reply to the stored baseline X post ID. If the baseline remote ID is missing, the worker fails closed and marks the event for reconciliation instead of retrying blindly.
- Live public-feed polling uses:
  - `CVE_CVE_ORG_DELTA_LOG_URL`
  - `CVE_CVE_ORG_HTTP_TIMEOUT_SECONDS`

### Bootstrapping

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
docker compose up -d
```

### Running The App

Start the API:

```bash
.venv/bin/cve-api
```

Start the worker in a separate shell:

```bash
.venv/bin/cve-worker
```

### Autonomous Runtime

Single-server autonomous production keeps the current queue architecture and uses external scheduling instead of an internal scheduler.

- Continuous process:
  - `.venv/bin/cve-worker`
- Scheduled once-run commands:
  - `.venv/bin/cve-ingest-poll-once`
  - `.venv/bin/cve-stale-refresh-once`
  - `.venv/bin/cve-alert-eval-once`
- Equivalent subcommands are also available through `.venv/bin/cve-runtime`.

Recommended cadence:

- ingest polling: every 10 minutes
- stale evidence refresh: every hour
- alert evaluation: every 5 minutes and after runtime repairs

Operational notes:

- `cve-ingest-poll-once` polls the public `cvelistV5` delta log, persists durable source checkpoint state, records success/no-op/failure metrics, and enqueues post-enrichment workflow jobs for newly classified CVEs.
- `cve-stale-refresh-once` recomputes stale evidence summaries and enqueues update publications through the existing publish queue when the current policy and publish state permit it.
- `cve-alert-eval-once` materializes replayable alert state from stored metrics, publication events, and audit trails.
- Autonomous X publication still depends on the continuous worker being healthy. The scheduled commands enqueue work; they do not replace the worker.
- Reconciliation-required X publication failures remain fail-closed. Operators must reconcile first instead of rerunning publish commands blindly.

Deployment runbook and timer examples live in [runbooks/autonomous-production.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/autonomous-production.md).

### Verification

Check the stack:

```bash
docker compose ps
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
```

Run the Phase 0 integration gate:

```bash
.venv/bin/pytest -q tests/integration
```

Run the autonomous runtime gate:

```bash
.venv/bin/pytest -q tests/integration/test_live_ingestion.py tests/unit/test_runtime.py
```

### Shutdown And Cleanup

Stop local services:

```bash
docker compose down
```

If old Compose containers from this project reappear, use:

```bash
docker compose down --remove-orphans
```
