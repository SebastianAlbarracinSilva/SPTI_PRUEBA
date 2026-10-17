"""Arquitectura Secure: LangGraph intercepta cada tool_call ANTES de ejecutarla.

    agent ──(tool_calls)──► supervisor_rbac ──(algún ALLOW)──► tools ──► agent
      │                         │                               │
      └──(sin tool_calls)► END  └──(todo DENY)──► deny_handler ◄┘(algún DENY)
                                                     └──► END  (DENY_MODE=terminate)

El LLM solo escribe en `messages`. `auth` lo inyecta FastAPI y ningún nodo
lo modifica (R1). La decisión la toma Supervisor (determinista, sin LLM).
"""
from __future__ import annotations

import json
import operator
from dataclasses import dataclass, field, replace
from typing import Annotated, Any, Callable, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from .audit import AuditSink
from .identity import AuthContext
from .logging_setup import log
from .policy import ALLOW, DENY, PolicyEngine
from .services import PermissionDeniedError, execute_secure
from .supervisor import Supervisor
from .telemetry import Telemetry
from .tools import SYSTEM_PROMPT


class AgentState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    auth: AuthContext            # identidad confiable (solo lectura para los nodos)
    trace_id: str
    steps: int
    decisions: list[dict]        # decisiones del último lote de tool_calls
    attempts: Annotated[list[dict], operator.add]   # historial acumulado de la ejecución
    blocked: bool


@dataclass
class SecureAgentDeps:
    llm: Any                     # Runnable con bind_tools
    supervisor: Supervisor
    engine: PolicyEngine
    audit: AuditSink
    telemetry: Telemetry
    executor: Callable[[AuthContext, str, dict], dict] | None = None
    deny_mode: str = "terminate"
    max_steps: int = 6
    architecture: str = "secure"
    _graph: Any = field(default=None, repr=False)

    def execute(self, auth: AuthContext, tool: str, args: dict) -> dict:
        if self.executor is not None:
            return self.executor(auth, tool, args)
        return execute_secure(self.engine, auth, tool, args)


def _usage(ai: AIMessage) -> dict[str, int | None]:
    u = getattr(ai, "usage_metadata", None) or {}
    return {"prompt_tokens": u.get("input_tokens"), "completion_tokens": u.get("output_tokens"),
            "total_tokens": u.get("total_tokens")}


def _denial_message(d: dict) -> ToolMessage:
    return ToolMessage(
        content=json.dumps({"error": "DENIED_BY_SUPERVISOR", "rule_id": d["rule_id"], "reason": d["reason"]},
                           ensure_ascii=False),
        tool_call_id=d["tool_call_id"], name=d["tool_name"], status="error",
    )


def build_graph(deps: SecureAgentDeps):
    tele = deps.telemetry

    # ------------------------------------------------------------ nodos
    def agent(state: AgentState, config) -> dict:
        auth = state["auth"]
        system = SystemMessage(SYSTEM_PROMPT.format(username=auth.username, role=auth.role))
        ai = deps.llm.invoke([system, *state["messages"]], config=config)
        return {"messages": [ai], "steps": state["steps"] + 1}

    def supervisor_rbac(state: AgentState) -> dict:
        auth, trace_id = state["auth"], state["trace_id"]
        ai: AIMessage = state["messages"][-1]
        usage = _usage(ai)
        proposals = [(tc["id"], tc["name"], tc["args"]) for tc in ai.tool_calls]
        # Llamadas mal formadas (JSON inválido) también pasan por el Supervisor => DENY-ARGS
        proposals += [(tc.get("id"), tc.get("name") or "?", tc.get("args")) for tc in ai.invalid_tool_calls]

        decisions = []
        for call_id, name, args in proposals:
            base = {"trace_id": trace_id, "architecture": deps.architecture, "user_id": auth.user_id,
                    "username": auth.username, "user_role": auth.role, "tool_call_id": call_id,
                    "tool_name": name, "tool_args": args}
            tele.tool_attempt(trace_id, **base, **usage)
            log.info("tool_attempt", **base)

            d = deps.supervisor.authorize(auth, name, args)
            entry = {**base, "decision": d.decision, "rule_id": d.rule_id, "reason": d.reason,
                     "policy_version": d.policy_version, "authz_latency_ms": d.latency_ms, **usage}
            try:
                audit_id = deps.audit.record_decision(entry)
            except Exception as exc:  # noqa: BLE001 — sin registro no hay ejecución (fail-closed)
                log.error("audit_write_failed", trace_id=trace_id, error=str(exc))
                d = replace(d, decision=DENY, rule_id="DENY-FAILSAFE-003",
                            reason="Audit Log no disponible: fail-closed", args=None)
                entry.update(decision=d.decision, rule_id=d.rule_id, reason=d.reason)
                audit_id = None

            log.info("authz_decision", **{k: entry[k] for k in (
                "trace_id", "user_id", "user_role", "tool_name", "decision", "rule_id", "authz_latency_ms")})
            tele.authz_decision(trace_id, **{k: v for k, v in entry.items() if k != "tool_args"})
            if d.lockout_triggered:
                alert = {"alert": "repeated_unauthorized_attempts", "user_id": auth.user_id,
                         "user_role": auth.role, "rule_id": "DENY-RATE-001"}
                log.warning("security_alert", trace_id=trace_id, **alert)
                tele.security_alert(trace_id, **alert)

            decisions.append({"tool_call_id": call_id, "tool_name": name, "args": d.args if d.allowed else args,
                              "decision": d.decision, "rule_id": d.rule_id, "reason": d.reason,
                              "audit_id": audit_id, "authz_latency_ms": d.latency_ms})
        return {"decisions": decisions, "attempts": decisions}

    def tools(state: AgentState) -> dict:
        auth, trace_id = state["auth"], state["trace_id"]
        out: list[ToolMessage] = []
        for d in state["decisions"]:
            if d["decision"] != ALLOW:
                out.append(_denial_message(d))
                continue
            error = None
            try:
                result = deps.execute(auth, d["tool_name"], d["args"])
                status, content = "ok", json.dumps(result, ensure_ascii=False, default=str)
            except PermissionDeniedError as exc:   # barrera 2 (servicio) — no debería ocurrir tras ALLOW
                status, error = "denied_by_service", str(exc)
                content = json.dumps({"error": "DENIED_BY_SERVICE", "detail": error}, ensure_ascii=False)
            except Exception as exc:  # noqa: BLE001
                status, error = "error", f"{type(exc).__name__}: {exc}"
                content = json.dumps({"error": "EXECUTION_ERROR", "detail": error}, ensure_ascii=False)
            if d.get("audit_id"):
                try:
                    deps.audit.record_execution(d["audit_id"], status == "ok", status, error)
                except Exception as exc:  # noqa: BLE001
                    log.error("audit_update_failed", trace_id=trace_id, error=str(exc))
            log.info("tool_execution", trace_id=trace_id, tool_name=d["tool_name"], status=status)
            tele.tool_execution(trace_id, tool_name=d["tool_name"], tool_call_id=d["tool_call_id"],
                                status=status, error=error, user_role=auth.role)
            out.append(ToolMessage(content=content, tool_call_id=d["tool_call_id"], name=d["tool_name"],
                                   status="success" if status == "ok" else "error"))
        return {"messages": out}

    def deny_handler(state: AgentState) -> dict:
        answered = {m.tool_call_id for m in state["messages"] if isinstance(m, ToolMessage)}
        msgs: list[AnyMessage] = [_denial_message(d) for d in state["decisions"]
                                  if d["decision"] != ALLOW and d["tool_call_id"] not in answered]
        if deps.deny_mode == "feedback":
            return {"messages": msgs}
        denied = [d for d in state["decisions"] if d["decision"] != ALLOW]
        detail = "; ".join(f"{d['tool_name']} → {d['rule_id']}" for d in denied)
        msgs.append(AIMessage(content=f"Acción bloqueada por el Supervisor RBAC ({detail}). "
                                      "La solicitud no fue ejecutada y quedó registrada en el Audit Log."))
        return {"messages": msgs, "blocked": True}

    # ------------------------------------------------------- aristas
    def after_agent(state: AgentState) -> str:
        ai = state["messages"][-1]
        return "supervisor_rbac" if (ai.tool_calls or ai.invalid_tool_calls) else END

    def after_supervisor(state: AgentState) -> str:
        return "tools" if any(d["decision"] == ALLOW for d in state["decisions"]) else "deny_handler"

    def after_tools(state: AgentState) -> str:
        if any(d["decision"] != ALLOW for d in state["decisions"]):
            return "deny_handler"
        return END if state["steps"] >= deps.max_steps else "agent"

    def after_deny(state: AgentState) -> str:
        if deps.deny_mode == "feedback" and state["steps"] < deps.max_steps:
            return "agent"
        return END

    g = StateGraph(AgentState)
    g.add_node("agent", agent)
    g.add_node("supervisor_rbac", supervisor_rbac)
    g.add_node("tools", tools)
    g.add_node("deny_handler", deny_handler)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", after_agent, ["supervisor_rbac", END])
    g.add_conditional_edges("supervisor_rbac", after_supervisor, ["tools", "deny_handler"])
    g.add_conditional_edges("tools", after_tools, ["agent", "deny_handler", END])
    g.add_conditional_edges("deny_handler", after_deny, ["agent", END])
    return g.compile()


def run_secure(deps: SecureAgentDeps, auth: AuthContext, message: str, trace_id: str,
               history: list[AnyMessage] | None = None, session_id: str | None = None) -> dict:
    if deps._graph is None:
        deps._graph = build_graph(deps)
    deps.telemetry.start_request(trace_id, architecture=deps.architecture, user_id=auth.user_id,
                                 username=auth.username, role=auth.role, message=message, session_id=session_id)
    handler = deps.telemetry.callback_handler(trace_id)
    config = {"recursion_limit": 4 * deps.max_steps + 4, "run_name": "secure_agent_graph",
              "callbacks": [handler] if handler else []}
    final = deps._graph.invoke(
        {"messages": [*(history or []), HumanMessage(message)], "auth": auth, "trace_id": trace_id,
         "steps": 0, "decisions": [], "attempts": [], "blocked": False},
        config=config,
    )
    last = final["messages"][-1]
    answer = last.content if isinstance(last, AIMessage) and last.content else "Se alcanzó el límite de pasos del agente."
    deps.telemetry.end_request(trace_id, answer=answer, blocked=final["blocked"])
    return {"answer": answer, "blocked": final["blocked"], "attempts": final["attempts"],
            "messages": final["messages"]}
