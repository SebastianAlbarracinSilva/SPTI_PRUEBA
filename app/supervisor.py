"""Supervisor / Permission Validator.

Envuelve al PolicyEngine con las garantías operativas:
- Fail-closed (R3): excepción, resultado inválido o tiempo excedido => DENY.
- Bloqueo por intentos repetidos (T05): K DENY en W segundos => lockout L.
- Mide la latencia de cada decisión (R7).

Es 100 % en memoria: no hace I/O en la ruta crítica de la decisión.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .identity import AuthContext
from .policy import ALLOW, DENY, PolicyEngine, PolicyResult


@dataclass(frozen=True)
class Decision:
    decision: str
    rule_id: str
    reason: str
    tool_name: str
    latency_ms: float
    policy_version: str
    args: dict[str, Any] | None = None
    lockout_triggered: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class LockoutTracker:
    """Ventana deslizante de DENY por usuario (in-memory, thread-safe)."""

    def __init__(self, max_denies: int, window_seconds: float, lockout_seconds: float,
                 clock: Callable[[], float] = time.monotonic):
        self.k, self.window, self.lockout = max_denies, window_seconds, lockout_seconds
        self.clock = clock
        self._denies: dict[int, deque[float]] = defaultdict(deque)
        self._locked_until: dict[int, float] = {}
        self._lock = threading.Lock()

    def is_locked(self, user_id: int) -> bool:
        with self._lock:
            until = self._locked_until.get(user_id)
            if until is None:
                return False
            if self.clock() >= until:
                del self._locked_until[user_id]
                return False
            return True

    def register_deny(self, user_id: int) -> bool:
        """Registra un DENY. Devuelve True si este DENY activa el bloqueo."""
        if self.k <= 0:
            return False
        now = self.clock()
        with self._lock:
            q = self._denies[user_id]
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.k and user_id not in self._locked_until:
                self._locked_until[user_id] = now + self.lockout
                q.clear()
                return True
        return False

    def reset(self) -> None:
        with self._lock:
            self._denies.clear()
            self._locked_until.clear()


class Supervisor:
    def __init__(self, engine: PolicyEngine, timeout_ms: float = 50.0,
                 lockout: LockoutTracker | None = None):
        self.engine = engine
        self.timeout_ms = timeout_ms
        rl = engine.rate_limit
        self.lockout = lockout or LockoutTracker(
            int(rl.get("max_denies", 0)), float(rl.get("window_seconds", 300)), float(rl.get("lockout_seconds", 600))
        )

    def authorize(self, auth: AuthContext | None, tool_name: str, args: Any) -> Decision:
        t0 = time.perf_counter()
        version = getattr(self.engine, "version", "unknown")
        try:
            if not isinstance(auth, AuthContext):
                result = PolicyResult(DENY, "DENY-AUTH-001", "Sin contexto de identidad autenticado")
            elif self.lockout.is_locked(auth.user_id):
                result = PolicyResult(DENY, "DENY-RATE-001", "Usuario bloqueado temporalmente por intentos no autorizados repetidos")
            else:
                result = self.engine.evaluate(auth.role, tool_name, args)
            # Resultado inválido => fail-closed
            if not isinstance(result, PolicyResult) or result.decision not in (ALLOW, DENY) or not result.rule_id:
                result = PolicyResult(DENY, "DENY-FAILSAFE-001", "Resultado inválido del motor de políticas")
        except Exception as exc:  # noqa: BLE001 — cualquier fallo => DENY
            result = PolicyResult(DENY, "DENY-FAILSAFE-001", f"Error del supervisor: {type(exc).__name__}")

        latency_ms = (time.perf_counter() - t0) * 1000
        if result.decision == ALLOW and latency_ms > self.timeout_ms:
            result = PolicyResult(DENY, "DENY-FAILSAFE-002",
                                  f"Decisión excedió el presupuesto ({latency_ms:.2f} ms > {self.timeout_ms} ms)")

        triggered = False
        if result.decision == DENY and isinstance(auth, AuthContext) and result.rule_id != "DENY-RATE-001":
            triggered = self.lockout.register_deny(auth.user_id)

        return Decision(
            decision=result.decision, rule_id=result.rule_id, reason=result.reason, tool_name=tool_name,
            latency_ms=round(latency_ms, 4), policy_version=version,
            args=result.args if result.decision == ALLOW else None, lockout_triggered=triggered,
        )
