"""Supervisor: fail-closed (R3), lockout por intentos repetidos (T05), latencia (R7)."""
import time

from app.policy import PolicyResult
from app.supervisor import LockoutTracker, Supervisor
from tests.conftest import ADMIN, SUPPORT


class _Boom:
    version = "x"
    rate_limit = {}

    def evaluate(self, *a):
        raise RuntimeError("fallo interno")


class _Garbage(_Boom):
    def evaluate(self, *a):
        return {"decision": "ALLOW"}   # tipo incorrecto


class _Slow(_Boom):
    def evaluate(self, *a):
        time.sleep(0.08)
        return PolicyResult("ALLOW", "RBAC-X", "ok", {})


def test_fail_closed_on_exception():
    d = Supervisor(_Boom()).authorize(ADMIN, "query_customers", {})
    assert (d.decision, d.rule_id) == ("DENY", "DENY-FAILSAFE-001")


def test_fail_closed_on_invalid_result():
    d = Supervisor(_Garbage()).authorize(ADMIN, "query_customers", {})
    assert (d.decision, d.rule_id) == ("DENY", "DENY-FAILSAFE-001")


def test_fail_closed_on_timeout():
    d = Supervisor(_Slow(), timeout_ms=50).authorize(ADMIN, "query_customers", {})
    assert (d.decision, d.rule_id) == ("DENY", "DENY-FAILSAFE-002")


def test_missing_identity_denied(engine):
    d = Supervisor(engine).authorize(None, "query_customers", {})
    assert (d.decision, d.rule_id) == ("DENY", "DENY-AUTH-001")


def test_lockout_after_k_denies(engine):
    clock = [0.0]
    sup = Supervisor(engine, lockout=LockoutTracker(3, 300, 600, clock=lambda: clock[0]))
    rules = [sup.authorize(SUPPORT, "delete_customer", {"customer_id": 1}) for _ in range(3)]
    assert [r.rule_id for r in rules] == ["DENY-RBAC-001"] * 3
    assert rules[-1].lockout_triggered
    # Durante el bloqueo incluso la acción legítima se deniega
    d = sup.authorize(SUPPORT, "query_customers", {"search": ""})
    assert (d.decision, d.rule_id) == ("DENY", "DENY-RATE-001")
    # Otro usuario no se ve afectado
    assert sup.authorize(ADMIN, "query_customers", {"search": ""}).decision == "ALLOW"
    # Al expirar el bloqueo se recupera el acceso
    clock[0] = 601
    assert sup.authorize(SUPPORT, "query_customers", {"search": ""}).decision == "ALLOW"


def test_denies_outside_window_do_not_accumulate(engine):
    clock = [0.0]
    sup = Supervisor(engine, lockout=LockoutTracker(3, 300, 600, clock=lambda: clock[0]))
    for t in (0, 200, 400, 600):
        clock[0] = t
        d = sup.authorize(SUPPORT, "delete_customer", {"customer_id": 1})
        assert not d.lockout_triggered


def test_latency_budget(engine):
    sup = Supervisor(engine)
    samples = sorted(sup.authorize(ADMIN, "modify_balance", {"customer_id": 1, "amount": 10, "reason": "abc"}).latency_ms
                     for _ in range(2000))
    assert samples[int(0.95 * len(samples))] < 50
