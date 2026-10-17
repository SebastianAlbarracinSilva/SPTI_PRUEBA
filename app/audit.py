"""Audit Log propio (fuente de verdad de la trazabilidad).

Escritura SÍNCRONA y obligatoria: si el registro de la decisión falla, la
herramienta no se ejecuta (fail-closed). Es independiente de Langfuse.
"""
from __future__ import annotations

import json
import threading
from typing import Any, Protocol

from .db import connection

_COLUMNS = (
    "trace_id", "architecture", "user_id", "username", "user_role", "tool_call_id", "tool_name",
    "tool_args", "decision", "rule_id", "reason", "policy_version", "authz_latency_ms",
    "prompt_tokens", "completion_tokens", "total_tokens",
)


class AuditSink(Protocol):
    def record_decision(self, entry: dict[str, Any]) -> int: ...
    def record_execution(self, audit_id: int, executed: bool, status: str, error: str | None = None) -> None: ...


class PostgresAuditSink:
    def record_decision(self, entry: dict[str, Any]) -> int:
        values = [entry.get(c) for c in _COLUMNS]
        values[_COLUMNS.index("tool_args")] = json.dumps(entry.get("tool_args"), ensure_ascii=False, default=str)
        sql = (f"INSERT INTO audit_log ({', '.join(_COLUMNS)}) "
               f"VALUES ({', '.join(['%s'] * len(_COLUMNS))}) RETURNING id")
        with connection() as conn:
            return conn.execute(sql, values).fetchone()["id"]

    def record_execution(self, audit_id: int, executed: bool, status: str, error: str | None = None) -> None:
        with connection() as conn:
            conn.execute(
                "UPDATE audit_log SET executed=%s, execution_status=%s, execution_error=%s WHERE id=%s",
                (executed, status, error, audit_id),
            )


class MemoryAuditSink:
    """Para pruebas unitarias sin PostgreSQL."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record_decision(self, entry: dict[str, Any]) -> int:
        with self._lock:
            self.rows.append({**entry, "id": len(self.rows) + 1, "executed": False, "execution_status": None})
            return len(self.rows)

    def record_execution(self, audit_id: int, executed: bool, status: str, error: str | None = None) -> None:
        with self._lock:
            self.rows[audit_id - 1].update(executed=executed, execution_status=status, execution_error=error)
