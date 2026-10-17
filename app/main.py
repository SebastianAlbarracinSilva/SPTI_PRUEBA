"""API FastAPI de la demo (Unsecure vs Secure)."""
from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent_secure import SecureAgentDeps, run_secure
from .agent_unsecure import run_unsecure
from .audit import PostgresAuditSink
from .auth import authenticate, get_auth_context, issue_token
from .config import ROOT, settings
from .db import connection, reset_seed
from .identity import AuthContext
from .logging_setup import configure_logging, log
from .policy import PolicyEngine
from .services import PermissionDeniedError, execute_secure
from .supervisor import Supervisor
from .telemetry import Telemetry, new_trace_id
from .tools import build_llm


class AppState:
    engine: PolicyEngine
    supervisor: Supervisor
    telemetry: Telemetry
    audit: PostgresAuditSink
    llm: Any = None
    secure: SecureAgentDeps | None = None
    sessions: dict[tuple, list] = {}
    sessions_lock = threading.Lock()


S = AppState()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    configure_logging()
    S.engine = PolicyEngine.from_file(settings.policy_path)   # política cacheada en memoria (R7)
    S.supervisor = Supervisor(S.engine, timeout_ms=settings.authz_timeout_ms)
    S.telemetry = Telemetry()
    S.audit = PostgresAuditSink()
    log.info("startup", policy_version=S.engine.version, langfuse_enabled=S.telemetry.enabled,
             deny_mode=settings.deny_mode, model=settings.model_name)
    yield
    S.telemetry.flush()


app = FastAPI(title="SPTI — Supervisión de agentes de IA", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")


def _llm():
    if S.llm is None:
        try:
            S.llm = build_llm()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(500, f"No se pudo crear el LLM (¿OPENAI_API_KEY en .env?): {exc}") from exc
    return S.llm


def _secure_deps() -> SecureAgentDeps:
    if S.secure is None:
        S.secure = SecureAgentDeps(llm=_llm(), supervisor=S.supervisor, engine=S.engine, audit=S.audit,
                                   telemetry=S.telemetry, deny_mode=settings.deny_mode,
                                   max_steps=settings.max_agent_steps)
    return S.secure


# ------------------------------------------------------------------ modelos
class LoginIn(BaseModel):
    username: str
    password: str


class ChatIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    architecture: Literal["secure", "unsecure"] = "secure"
    session_id: str | None = Field(None, max_length=64, description="Para conversaciones multi-turno")


class ResetIn(BaseModel):
    clear_audit: bool = False


# ------------------------------------------------------------------ rutas
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(ROOT / "app" / "static" / "index.html")


@app.get("/health")
def health():
    with connection() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "policy_version": S.engine.version, "langfuse_enabled": S.telemetry.enabled,
            "llm_provider": settings.llm_provider, "model": settings.model_name,
            "telemetry_dropped": S.telemetry.dropped}


@app.post("/auth/login")
def login(body: LoginIn):
    auth = authenticate(body.username, body.password)
    if auth is None:
        raise HTTPException(401, "Credenciales inválidas")
    return {"access_token": issue_token(auth), "token_type": "bearer", "username": auth.username, "role": auth.role}


@app.get("/auth/me")
def me(auth: AuthContext = Depends(get_auth_context)):
    return {"user_id": auth.user_id, "username": auth.username, "role": auth.role}


@app.post("/api/chat")
def chat(body: ChatIn, auth: AuthContext = Depends(get_auth_context)):
    trace_id = new_trace_id()
    key = (auth.user_id, body.architecture, body.session_id) if body.session_id else None
    with S.sessions_lock:
        history = list(S.sessions.get(key, [])) if key else []

    if body.architecture == "secure":
        result = run_secure(_secure_deps(), auth, body.message, trace_id, history, body.session_id)
    else:
        result = run_unsecure(_llm(), S.audit, S.telemetry, auth, body.message, trace_id, history,
                              body.session_id, settings.max_agent_steps)

    if key:
        with S.sessions_lock:
            S.sessions[key] = result["messages"][-40:]
    return {"trace_id": trace_id, "architecture": body.architecture, "user": auth.username, "role": auth.role,
            "answer": result["answer"], "blocked": result["blocked"],
            "attempts": [{k: v for k, v in a.items() if k != "audit_id"} for a in result["attempts"]],
            "langfuse_url": S.telemetry.trace_url(trace_id)}


@app.post("/api/tools/{tool_name}")
def direct_tool(tool_name: str, args: dict[str, Any], auth: AuthContext = Depends(get_auth_context)):
    """Llama a la capa de servicios SIN pasar por LangGraph (prueba de R5)."""
    trace_id = new_trace_id()
    entry = {"trace_id": trace_id, "architecture": "direct_api", "user_id": auth.user_id, "username": auth.username,
             "user_role": auth.role, "tool_name": tool_name, "tool_args": args, "policy_version": S.engine.version}
    try:
        result = execute_secure(S.engine, auth, tool_name, args)
    except PermissionDeniedError as exc:
        S.audit.record_decision({**entry, "decision": "DENY", "rule_id": exc.rule_id, "reason": exc.reason})
        log.warning("direct_api_denied", trace_id=trace_id, tool_name=tool_name, user_role=auth.role, rule_id=exc.rule_id)
        raise HTTPException(403, {"decision": "DENY", "rule_id": exc.rule_id, "reason": exc.reason}) from exc
    audit_id = S.audit.record_decision({**entry, "decision": "ALLOW", "rule_id": "SERVICE-RECHECK", "reason": "ok"})
    S.audit.record_execution(audit_id, True, "ok")
    return {"trace_id": trace_id, "decision": "ALLOW", "result": result}


@app.get("/api/metrics")
def metrics():
    with connection() as conn:
        rows = conn.execute("""
            SELECT architecture,
                   count(*)                                     AS attempts,
                   count(*) FILTER (WHERE decision='ALLOW')     AS allow,
                   count(*) FILTER (WHERE decision='DENY')      AS deny,
                   count(*) FILTER (WHERE executed)             AS executed,
                   percentile_cont(0.50) WITHIN GROUP (ORDER BY authz_latency_ms) AS authz_p50_ms,
                   percentile_cont(0.95) WITHIN GROUP (ORDER BY authz_latency_ms) AS authz_p95_ms,
                   percentile_cont(0.99) WITHIN GROUP (ORDER BY authz_latency_ms) AS authz_p99_ms
            FROM audit_log GROUP BY architecture ORDER BY architecture""").fetchall()
    return {"by_architecture": rows}


# ------------------------------------------------------------- demo / QA
def _demo_only():
    if not settings.demo_mode:
        raise HTTPException(404)


@app.get("/api/demo/state", dependencies=[Depends(_demo_only)])
def demo_state(limit: int = 25):
    with connection() as conn:
        return {
            "customers": conn.execute("SELECT id, full_name, email, document_id, balance::float AS balance FROM customers ORDER BY id").fetchall(),
            "users": conn.execute("SELECT id, username, role FROM app_users ORDER BY id").fetchall(),
            "tickets": conn.execute("SELECT count(*) AS n FROM tickets").fetchone()["n"],
            "audit": conn.execute(
                "SELECT id, ts, trace_id, architecture, username, user_role, tool_name, tool_args, decision, rule_id, "
                "authz_latency_ms, total_tokens, executed, execution_status FROM audit_log ORDER BY id DESC LIMIT %s",
                (limit,)).fetchall(),
            "db_changes": conn.execute(
                "SELECT id, ts, table_name, op, row_pk, db_role FROM db_change_log ORDER BY id DESC LIMIT 15").fetchall(),
            "langfuse_enabled": S.telemetry.enabled,
        }


@app.post("/api/demo/reset", dependencies=[Depends(_demo_only)])
def demo_reset(body: ResetIn | None = None):
    reset_seed()
    S.supervisor.lockout.reset()
    with S.sessions_lock:
        S.sessions.clear()
    if body and body.clear_audit:
        with connection() as conn:
            conn.execute("TRUNCATE audit_log, db_change_log RESTART IDENTITY")
    log.info("demo_reset", clear_audit=bool(body and body.clear_audit))
    return {"status": "reset"}


@app.get("/api/demo/audit/{trace_id}", dependencies=[Depends(_demo_only)])
def audit_by_trace(trace_id: str):
    with connection() as conn:
        return conn.execute("SELECT * FROM audit_log WHERE trace_id=%s ORDER BY id", (trace_id,)).fetchall()
