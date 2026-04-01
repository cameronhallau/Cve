from __future__ import annotations

from uuid import uuid4

from redis import Redis
from rq import Queue, SimpleWorker

from cve_service.workers.jobs import noop_job


def test_worker_processes_noop_job(redis_url: str) -> None:
    redis_client = Redis.from_url(redis_url)
    queue = Queue(name=f"phase0-noop-{uuid4().hex}", connection=redis_client)
    job = queue.enqueue(noop_job, {"probe": "phase0"})

    worker = SimpleWorker([queue], connection=redis_client)
    worker.work(burst=True)
    job.refresh()

    try:
        assert job.is_finished is True
        assert job.return_value() == {"status": "processed", "payload": {"probe": "phase0"}}
    finally:
        job.delete()
        redis_client.close()
