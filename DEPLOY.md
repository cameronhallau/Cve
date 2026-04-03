# Deploy Checklist

## Scope

Use this checklist for the first single-server autonomous production rollout on X.

## 1. Prepare The Host

- clone the repo to `/srv/cve/Cve` or choose a different fixed path
- create the virtualenv:
  - `python3.12 -m venv .venv`
- install the app:
  - `.venv/bin/python -m pip install --upgrade pip`
  - `.venv/bin/python -m pip install -e '.[dev]'`
- provision PostgreSQL and Redis

## 2. Configure Secrets

- start from:
  - [.env.production.example](/home/cam/Documents/Github/Vuln/Cve/.env.production.example)
- write the real env file to:
  - `/etc/cve-service/cve.env`
- set:
  - `CVE_DATABASE_URL`
  - `CVE_REDIS_URL`
  - `CVE_RQ_QUEUE_NAME`
  - `CVE_EXTERNAL_ENRICHMENT_ENABLED=true`
  - `CVE_VULNCHECK_KEV_URL`
  - `VULNCHECK_API_KEY`
  - `CVE_EPSS_URL`
  - `CVE_GITHUB_POC_ENABLED=false`
  - `CVE_SEARCHSPLOIT_BINARY_PATH`
  - `CVE_EXPLOITDB_SEARCH_URL`
  - `OPENROUTER_API_KEY`
  - `CVE_PUBLISH_TARGET_NAME=x`
  - `CVE_X_AUTH_MODE=oauth1_user`
  - `CVE_X_CONSUMER_KEY`
  - `CVE_X_CONSUMER_SECRET`
  - `CVE_X_ACCESS_TOKEN`
  - `CVE_X_ACCESS_TOKEN_SECRET`
- optional only if you explicitly enable GitHub PoC matching:
  - `CVE_GITHUB_POC_ENABLED=true`
  - `CVE_GITHUB_API_BASE_URL`
  - `CVE_GITHUB_API_VERSION`
  - `GITHUB_TOKEN`

## 2a. Install SearchSploit

Ubuntu-class hosts usually do not provide a `searchsploit` package directly. Install it from the Exploit-DB repo:

```bash
sudo apt-get update
sudo apt-get install -y git
sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb || sudo git -C /opt/exploitdb pull --ff-only
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
searchsploit --help
```

## 3. Install systemd Units

- copy:
  - [systemd/cve-api.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-api.service)
  - [systemd/cve-worker.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-worker.service)
  - [systemd/cve-ingest-poll.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-ingest-poll.service)
  - [systemd/cve-ingest-poll.timer](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-ingest-poll.timer)
  - [systemd/cve-stale-refresh.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-stale-refresh.service)
  - [systemd/cve-stale-refresh.timer](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-stale-refresh.timer)
  - [systemd/cve-alert-eval.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-alert-eval.service)
  - [systemd/cve-alert-eval.timer](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-alert-eval.timer)
- if your app path is not `/srv/cve/Cve`, update:
  - `WorkingDirectory`
  - `EnvironmentFile`
  - `ExecStart`

## 4. Enable The Runtime

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cve-api.service
sudo systemctl enable --now cve-worker.service
sudo systemctl enable --now cve-ingest-poll.timer
sudo systemctl enable --now cve-stale-refresh.timer
sudo systemctl enable --now cve-alert-eval.timer
```

## 5. Verify

- api:
  - `systemctl status cve-api.service`
- worker:
  - `systemctl status cve-worker.service`
- timers:
  - `systemctl list-timers 'cve-*'`
- one-shot dry checks:
  - `.venv/bin/cve-ingest-poll-once`
  - `.venv/bin/cve-stale-refresh-once`
  - `.venv/bin/cve-alert-eval-once`
- app health:
  - `curl http://127.0.0.1:8000/health/live`
  - `curl http://127.0.0.1:8000/health/ready`

## 6. Production Expectations

- keep `cve-worker.service` running continuously
- do not replace the timers with an internal scheduler
- do not rerun X publication work blindly when reconciliation is required
- use:
  - [runbooks/autonomous-production.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/autonomous-production.md)
  - [runbooks/ingestion-failure.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/ingestion-failure.md)
  - [runbooks/publish-failure.md](/home/cam/Documents/Github/Vuln/Cve/runbooks/publish-failure.md)

## 7. Rollback

- disable timers:
  - `sudo systemctl disable --now cve-ingest-poll.timer`
  - `sudo systemctl disable --now cve-stale-refresh.timer`
  - `sudo systemctl disable --now cve-alert-eval.timer`
- stop worker:
  - `sudo systemctl disable --now cve-worker.service`
- stop api:
  - `sudo systemctl disable --now cve-api.service`
- preserve:
  - `source_progress`
  - `audit_events`
  - `operational_metrics`
  - `publication_events`
