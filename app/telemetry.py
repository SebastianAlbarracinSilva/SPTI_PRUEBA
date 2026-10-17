"""Telemetría hacia Langfuse: SOLO observabilidad (R6).

- Ningún resultado de este módulo se usa para decidir ALLOW/DENY.
- Los eventos se encolan (put_nowait) y un hilo en segundo plano los envía;
  si la cola se llena o Langfuse cae, el evento se descarta y la petición
  continúa igual. Todas las llamadas están envueltas en try/except.
- Correlación: el trace_id (32 hex) se genera en la app, se guarda en el
  Audit Log y se usa como trace_id de Langfuse (trace_context).

SDK asumido: langfuse>=3,<4 (basado en OpenTelemetry).
"""
from __future__ import annotations

import queue
import threading
import uuid
from typing import Any

from .config import settings
from .logging_setup import log


def new_trace_id() -> str:
    return uuid.uuid4().hex  # 32 caracteres hex, formato válido de trace_id OTel/Langfuse


class Telemetry:
    def __init__(self, enabled: bool | None = None, max_queue: int = 10_000):
        self.enabled = settings.langfuse_enabled if enabled is None else enabled
        self.client = None
        self.dropped = 0
        self._q: queue.Queue = queue.Queue(maxsize=max_queue)
        if self.enabled:
            try:
                from langfuse import Langfuse
                # Langfuse Cloud v4: sin esta cabecera, los datos de SDKs < 4.7 pueden tardar hasta 15 min
                # en ser consultables por la API v2 de observaciones.
                self.client = Langfuse(additional_headers={"x-langfuse-ingestion-version": "4"})
                threading.Thread(target=self._warm_project_id, daemon=True).start()
            except Exception as exc:  # noqa: BLE001
                log.warning("langfuse_init_failed", error=str(exc))
                self.enabled = False
        threading.Thread(target=self._worker, name="telemetry-worker", daemon=True).start()

    # ------------------------------------------------------------- API
    def callback_handler(self, trace_id: str):
        """Handler de LangChain que registra las generaciones (con tokens) en la traza."""
        if not self.enabled:
            return None
        try:
            from langfuse.langchain import CallbackHandler
            return CallbackHandler(trace_context={"trace_id": trace_id})
        except Exception as exc:  # noqa: BLE001
            log.warning("langfuse_handler_failed", error=str(exc))
            return None

    def trace_url(self, trace_id: str) -> str | None:
        pid = getattr(self.client, "_project_id", None) if self.client else None
        base = getattr(self.client, "_base_url", None) if self.client else None
        return f"{base}/project/{pid}/traces/{trace_id}" if pid and base else None

    def start_request(self, trace_id: str, *, architecture: str, user_id: int, username: str,
                      role: str, message: str, session_id: str | None) -> None:
        self._emit("request", trace_id, architecture=architecture, user_id=user_id, username=username,
                   role=role, message=message, session_id=session_id)

    def tool_attempt(self, trace_id: str, /, **fields: Any) -> None:
        self._emit("tool_attempt", trace_id, **fields)

    def authz_decision(self, trace_id: str, /, **fields: Any) -> None:
        self._emit("authz_decision", trace_id, **fields)

    def tool_execution(self, trace_id: str, /, **fields: Any) -> None:
        self._emit("tool_execution", trace_id, **fields)

    def security_alert(self, trace_id: str, /, **fields: Any) -> None:
        """Control de DETECCIÓN: alerta, nunca bloquea."""
        self._emit("security_alert", trace_id, **fields)

    def end_request(self, trace_id: str, *, answer: str, blocked: bool) -> None:
        self._emit("response", trace_id, answer=answer, blocked=blocked)

    def flush(self) -> None:
        self._q.join()
        if self.client:
            try:
                self.client.flush()
            except Exception:  # noqa: BLE001
                pass

    # -------------------------------------------------------- interno
    def _emit(self, kind: str, trace_id: str, /, **fields: Any) -> None:
        try:
            self._enqueue((kind, trace_id, fields))
        except Exception:  # noqa: BLE001 — cola llena o cualquier fallo: se descarta, nunca se propaga
            self.dropped += 1

    def _enqueue(self, item: tuple) -> None:
        self._q.put_nowait(item)

    def _worker(self) -> None:
        while True:
            kind, trace_id, fields = self._q.get()
            try:
                if self.enabled and self.client:
                    self._send(kind, trace_id, fields)
            except Exception as exc:  # noqa: BLE001 — la caída de Langfuse no afecta a nada
                log.warning("langfuse_emit_failed", kind=kind, trace_id=trace_id, error=str(exc))
            finally:
                self._q.task_done()

    def _send(self, kind: str, trace_id: str, f: dict[str, Any]) -> None:
        ctx = {"trace_id": trace_id}
        lf = self.client
        if kind == "request":
            span = lf.start_span(trace_context=ctx, name="agent_request", input={"message": f["message"]},
                                 metadata={"architecture": f["architecture"], "user_role": f["role"]})
            span.update_trace(
                name=f"{f['architecture']}-agent", user_id=f["username"], session_id=f.get("session_id"),
                input={"message": f["message"]}, tags=[f["architecture"], f"role:{f['role']}"],
                metadata={"architecture": f["architecture"], "user_id": f["user_id"], "user_role": f["role"]},
            )
            span.end()
        elif kind == "tool_attempt":
            lf.create_event(trace_context=ctx, name=f"tool_attempt:{f['tool_name']}",
                            input={"tool_name": f["tool_name"], "tool_args": f.get("tool_args")}, metadata=f)
        elif kind == "authz_decision":
            lf.create_event(trace_context=ctx, name=f"authz_decision:{f['decision']}",
                            output={"decision": f["decision"], "rule_id": f["rule_id"], "reason": f.get("reason")},
                            metadata=f, level="WARNING" if f["decision"] == "DENY" else "DEFAULT")
        elif kind == "tool_execution":
            lf.create_event(trace_context=ctx, name=f"tool_execution:{f['tool_name']}", metadata=f,
                            output={"status": f.get("status")}, level="ERROR" if f.get("status") == "error" else "DEFAULT")
        elif kind == "security_alert":
            lf.create_event(trace_context=ctx, name=f"security_alert:{f.get('alert')}", metadata=f, level="ERROR")
        elif kind == "response":
            span = lf.start_span(trace_context=ctx, name="agent_response", output={"answer": f["answer"]},
                                 metadata={"blocked": f["blocked"]})
            span.update_trace(output={"answer": f["answer"], "blocked": f["blocked"]})
            span.end()

    def _warm_project_id(self) -> None:
        try:
            self.client._get_project_id()  # noqa: SLF001 — cachea el project id para construir URLs
        except Exception:  # noqa: BLE001
            pass
