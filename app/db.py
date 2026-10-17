"""Pool de conexiones a PostgreSQL."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import ROOT, settings

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(settings.database_url, min_size=1, max_size=10,
                               kwargs={"row_factory": dict_row}, open=True)
    return _pool


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    with get_pool().connection() as conn:
        yield conn


def reset_seed() -> None:
    sql = (ROOT / "db" / "02_seed.sql").read_text(encoding="utf-8")
    with connection() as conn:
        conn.execute(sql)
