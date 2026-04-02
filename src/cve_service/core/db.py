from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Callable

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from cve_service.core.config import Settings

AFTER_COMMIT_CALLBACKS_KEY = "after_commit_callbacks"


def create_db_engine(settings: Settings) -> Engine:
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": int(settings.health_timeout_seconds)},
    )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    session = session_factory()
    try:
        yield session
        session.commit()
        _run_after_commit_callbacks(session)
    except Exception:
        _clear_after_commit_callbacks(session)
        session.rollback()
        raise
    finally:
        session.close()


def ping_database(engine: Engine) -> tuple[bool, str]:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True, "connected"
    except Exception as exc:
        return False, str(exc)


def register_after_commit_callback(session: Session, callback: Callable[[], None]) -> None:
    callbacks = session.info.setdefault(AFTER_COMMIT_CALLBACKS_KEY, [])
    callbacks.append(callback)


def _run_after_commit_callbacks(session: Session) -> None:
    callbacks = session.info.pop(AFTER_COMMIT_CALLBACKS_KEY, [])
    for callback in callbacks:
        callback()


def _clear_after_commit_callbacks(session: Session) -> None:
    session.info.pop(AFTER_COMMIT_CALLBACKS_KEY, None)
