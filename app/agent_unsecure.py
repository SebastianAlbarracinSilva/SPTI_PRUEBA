"""Arquitectura Unsecure: el LLM decide e invoca herramientas directamente.

No hay Supervisor: cualquier tool_call propuesta se ejecuta contra la BD
con la conexión propietaria. Se registran los intentos (decision=NONE)
solo para poder medir y comparar; ese registro no es un control.
"""
from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage

from .audit import AuditSink
from .identity import AuthContext
from .logging_setup import log
from .services import execute_unsecure
from .telemetry import Telemetry
from .tools import SYSTEM_PROMPT


def run_unsecure(llm: Any, audit: AuditSink, telemetry: Telemetry, auth: AuthContext, message: str,
                 trace_id: str, history: list[AnyMessage] | None = None, session_id: str | None = None,
                 max_steps: int = 6, executor=execute_unsecure) -> dict:
    telemetry.start_request(trace_id, architecture="unsecure", user_id=auth.user_id, username=auth.username,
                            role=auth.role, message=message, session_id=session_id)
    handler = telemetry.callback_handler(trace_id)
    config = {"callbacks": [handler] if handler else [], "run_name": "unsecure_agent"}
    system = SystemMessage(SYSTEM_PROMPT.format(username=auth.username, role=auth.role))
    messages: list[AnyMessage] = [*(history or []), HumanMessage(message)]
    attempts: list[dict] = []

    for _ in range(max_steps):
        ai: AIMessage = llm.invoke([system, *messages], config=config)
        messages.append(ai)
        if not ai.tool_calls:
            break
        u = ai.usage_metadata or {}
        for tc in ai.tool_calls:
            entry = {"trace_id": trace_id, "architecture": "unsecure", "user_id": auth.user_id,
                     "username": auth.username, "user_role": auth.role, "tool_call_id": tc["id"],
                     "tool_name": tc["name"], "tool_args": tc["args"], "decision": "NONE", "rule_id": None,
                     "reason": "Sin validación externa (arquitectura insegura)",
                     "prompt_tokens": u.get("input_tokens"), "completion_tokens": u.get("output_tokens"),
                     "total_tokens": u.get("total_tokens")}
            telemetry.tool_attempt(trace_id, **entry)
            audit_id = audit.record_decision(entry)
            error = None
            try:
                result = executor(auth, tc["name"], tc["args"])
                status, content = "ok", json.dumps(result, ensure_ascii=False, default=str)
            except Exception as exc:  # noqa: BLE001
                status, error = "error", f"{type(exc).__name__}: {exc}"
                content = json.dumps({"error": error}, ensure_ascii=False)
            audit.record_execution(audit_id, status == "ok", status, error)
            log.info("tool_execution", trace_id=trace_id, architecture="unsecure", tool_name=tc["name"],
                     user_role=auth.role, status=status)
            telemetry.tool_execution(trace_id, tool_name=tc["name"], tool_call_id=tc["id"], status=status,
                                     error=error, user_role=auth.role)
            attempts.append({"tool_call_id": tc["id"], "tool_name": tc["name"], "args": tc["args"],
                             "decision": "NONE", "rule_id": None, "executed": status == "ok", "status": status})
            messages.append(ToolMessage(content=content, tool_call_id=tc["id"], name=tc["name"]))

    last = messages[-1]
    answer = last.content if isinstance(last, AIMessage) and last.content else "Se alcanzó el límite de pasos del agente."
    telemetry.end_request(trace_id, answer=answer, blocked=False)
    return {"answer": answer, "blocked": False, "attempts": attempts, "messages": messages}
