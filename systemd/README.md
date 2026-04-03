# systemd Units

These unit files provide the checked-in single-server production baseline for autonomous operation.

- [cve-api.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-api.service)
- [cve-worker.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-worker.service)
- [cve-ingest-poll.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-ingest-poll.service)
- [cve-ingest-poll.timer](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-ingest-poll.timer)
- [cve-stale-refresh.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-stale-refresh.service)
- [cve-stale-refresh.timer](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-stale-refresh.timer)
- [cve-alert-eval.service](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-alert-eval.service)
- [cve-alert-eval.timer](/home/cam/Documents/Github/Vuln/Cve/systemd/cve-alert-eval.timer)

Deployment assumptions:

- application root: `/srv/cve/Cve`
- environment file: `/etc/cve-service/cve.env`
- virtualenv: `/srv/cve/Cve/.venv`

If your deployment paths differ, update `WorkingDirectory`, `EnvironmentFile`, and `ExecStart` consistently across the checked-in units.
