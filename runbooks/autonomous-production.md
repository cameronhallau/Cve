# Autonomous Production Runbook

## Scope

Use this runbook for single-server autonomous production on X with:

- one continuous worker process
- external scheduling for ingest polling, stale refresh, and alert evaluation
- no dashboard or internal scheduler dependency

## Required Runtime

- continuous worker:
  - `.venv/bin/cve-worker`
- scheduled once-run commands:
  - `.venv/bin/cve-ingest-poll-once`
  - `.venv/bin/cve-stale-refresh-once`
  - `.venv/bin/cve-alert-eval-once`

## Required Configuration

- database and queue:
  - `CVE_DATABASE_URL`
  - `CVE_REDIS_URL`
  - `CVE_RQ_QUEUE_NAME`
- live CVE source:
  - `CVE_CVE_ORG_DELTA_LOG_URL`
  - `CVE_CVE_ORG_HTTP_TIMEOUT_SECONDS`
- publish target:
  - `CVE_PUBLISH_TARGET_NAME=x`
  - preferred unattended mode: `CVE_X_AUTH_MODE=oauth1_user`
  - required OAuth 1.0a secrets:
    - `CVE_X_CONSUMER_KEY`
    - `CVE_X_CONSUMER_SECRET`
    - `CVE_X_ACCESS_TOKEN`
    - `CVE_X_ACCESS_TOKEN_SECRET`

## Cadence

- ingest polling:
  - every 10 minutes
  - responsibility: pull new or updated CVEs, persist `source_progress`, and enqueue post-enrichment work
- stale refresh:
  - every hour
  - responsibility: reevaluate expired evidence summaries and enqueue update publications when material deltas exist
- alert evaluation:
  - every 5 minutes
  - responsibility: persist replayable alert state from current metrics, audit events, and publication outcomes

## systemd Example

Worker service:

```ini
[Unit]
Description=CVE autonomous worker
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/srv/cve/Cve
EnvironmentFile=/etc/cve-service/cve.env
ExecStart=/srv/cve/Cve/.venv/bin/cve-worker
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Ingest poll service and timer:

```ini
[Unit]
Description=CVE live ingest poll once
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/srv/cve/Cve
EnvironmentFile=/etc/cve-service/cve.env
ExecStart=/srv/cve/Cve/.venv/bin/cve-ingest-poll-once
```

```ini
[Unit]
Description=CVE live ingest poll timer

[Timer]
OnCalendar=*:0/10
Persistent=true

[Install]
WantedBy=timers.target
```

Stale refresh service and timer:

```ini
[Unit]
Description=CVE stale evidence refresh once
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/srv/cve/Cve
EnvironmentFile=/etc/cve-service/cve.env
ExecStart=/srv/cve/Cve/.venv/bin/cve-stale-refresh-once
```

```ini
[Unit]
Description=CVE stale evidence refresh timer

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Alert evaluation service and timer:

```ini
[Unit]
Description=CVE operational alert evaluation once
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/srv/cve/Cve
EnvironmentFile=/etc/cve-service/cve.env
ExecStart=/srv/cve/Cve/.venv/bin/cve-alert-eval-once
```

```ini
[Unit]
Description=CVE operational alert evaluation timer

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
```

## cron Example

```cron
*/10 * * * * cd /srv/cve/Cve && /srv/cve/Cve/.venv/bin/cve-ingest-poll-once >> /var/log/cve/ingest-poll.log 2>&1
0 * * * * cd /srv/cve/Cve && /srv/cve/Cve/.venv/bin/cve-stale-refresh-once >> /var/log/cve/stale-refresh.log 2>&1
*/5 * * * * cd /srv/cve/Cve && /srv/cve/Cve/.venv/bin/cve-alert-eval-once >> /var/log/cve/alert-eval.log 2>&1
```

## Failure Domains

- worker down:
  - queued post-enrichment or publication jobs will accumulate
  - scheduled once-run commands may still succeed locally but autonomous publication will stall
- poll failure:
  - `source_progress.cursor` does not advance
  - rerun is safe because ingest remains idempotent and queue handoff is deduplicated
- X publish reconciliation failure:
  - keep the worker running
  - do not rerun publish commands until the failed event is reconciled
- queue outage:
  - `cve-ingest-poll-once` and `cve-stale-refresh-once` should fail fast
  - repair Redis and rerun the missed command windows

## Recovery Expectations

- keep the worker enabled during normal recovery unless it is the fault domain
- use [ingestion-failure.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/ingestion-failure.md) for source cursor and parser issues
- use [publish-failure.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/publish-failure.md) for X reconciliation and publish retry control
- confirm `source_progress`, `audit_events`, `operational_metrics`, and `publication_events` before declaring recovery complete
