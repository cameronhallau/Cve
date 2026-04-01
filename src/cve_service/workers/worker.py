from __future__ import annotations

from rq import Worker

from cve_service.core.config import Settings, get_settings
from cve_service.core.queue import create_queue, create_redis_client


def build_worker(settings: Settings | None = None) -> Worker:
    app_settings = settings or get_settings()
    redis_client = create_redis_client(app_settings)
    queue = create_queue(app_settings, redis_client)
    return Worker([queue], connection=redis_client)


def run_worker() -> None:
    worker = build_worker()
    worker.work(burst=False, with_scheduler=False)


if __name__ == "__main__":
    run_worker()

