from __future__ import annotations

from redis import Redis
from rq import Queue

from cve_service.core.config import Settings


def create_redis_client(settings: Settings) -> Redis:
    return Redis.from_url(
        settings.redis_url,
        socket_connect_timeout=settings.health_timeout_seconds,
        socket_timeout=settings.health_timeout_seconds,
        decode_responses=False,
    )


def create_queue(settings: Settings, redis_client: Redis | None = None) -> Queue:
    connection = redis_client or create_redis_client(settings)
    return Queue(name=settings.rq_queue_name, connection=connection)


def ping_queue(redis_client: Redis, queue: Queue) -> tuple[bool, str]:
    try:
        if not redis_client.ping():
            return False, "redis ping returned false"
        queue.count
        return True, f"connected:{queue.name}"
    except Exception as exc:
        return False, str(exc)

