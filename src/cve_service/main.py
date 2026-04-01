from __future__ import annotations

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.engine import Engine

from cve_service.api.models import LiveResponse, ReadyResponse
from cve_service.core.config import Settings, get_settings
from cve_service.core.db import create_db_engine, ping_database
from cve_service.core.queue import create_queue, create_redis_client, ping_queue


def create_app(settings: Settings | None = None) -> FastAPI:
    app_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = create_db_engine(app_settings)
        redis_client = create_redis_client(app_settings)
        queue = create_queue(app_settings, redis_client)

        app.state.settings = app_settings
        app.state.engine = engine
        app.state.redis = redis_client
        app.state.queue = queue

        yield

        redis_client.close()
        engine.dispose()

    app = FastAPI(title=app_settings.app_name, lifespan=lifespan)

    @app.get("/health/live", response_model=LiveResponse)
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", response_model=ReadyResponse)
    async def ready(request: Request) -> JSONResponse:
        engine: Engine = request.app.state.engine
        redis_client = request.app.state.redis
        queue = request.app.state.queue

        db_ok, db_detail = ping_database(engine)
        queue_ok, queue_detail = ping_queue(redis_client, queue)
        overall = db_ok and queue_ok

        return JSONResponse(
            status_code=200 if overall else 503,
            content={
                "status": "ok" if overall else "degraded",
                "checks": {
                    "database": {"ok": db_ok, "detail": db_detail},
                    "queue": {"ok": queue_ok, "detail": queue_detail},
                },
            },
        )

    return app


app = create_app()


def run() -> None:
    uvicorn.run("cve_service.main:app", host="0.0.0.0", port=8000, reload=False)
