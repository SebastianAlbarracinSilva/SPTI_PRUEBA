"""Política RBAC: matriz completa rol × herramienta, deny-by-default y argumentos (R2, R4)."""
import pytest

from app.policy import ALLOW, DENY, PolicyEngine

VALID_ARGS = {
    "query_customers": {"search": "Ana"},
    "create_ticket": {"customer_id": 1, "subject": "Prueba", "description": "x"},
    "delete_customer": {"customer_id": 4},
    "modify_balance": {"customer_id": 2, "amount": 200, "reason": "compensación"},
    "export_all_data": {"format": "json"},
    "change_agent_role": {"username": "soporte1", "new_role": "admin"},
}

# Matriz esperada (contexto común), escrita a mano e independiente de policy.yaml
EXPECTED = {
    "support": {"query_customers", "create_ticket"},
    "admin": {"query_customers", "create_ticket", "delete_customer", "modify_balance", "export_all_data"},
}


@pytest.mark.parametrize("role", ["support", "admin"])
@pytest.mark.parametrize("tool", list(VALID_ARGS))
def test_matrix(engine, role, tool):
    r = engine.evaluate(role, tool, VALID_ARGS[tool])
    assert r.decision == (ALLOW if tool in EXPECTED[role] else DENY), r


def test_change_agent_role_denied_for_everyone(engine):
    for role in ("support", "admin"):
        r = engine.evaluate(role, "change_agent_role", VALID_ARGS["change_agent_role"])
        assert (r.decision, r.rule_id) == (DENY, "DENY-FORBIDDEN-001")


@pytest.mark.parametrize("role", [None, "", "superadmin", "Admin", "root"])
def test_unknown_role_denied(engine, role):
    r = engine.evaluate(role, "query_customers", {"search": ""})
    assert (r.decision, r.rule_id) == (DENY, "DENY-ROLE-001")


def test_unknown_tool_denied(engine):
    r = engine.evaluate("admin", "drop_database", {})
    assert (r.decision, r.rule_id) == (DENY, "DENY-TOOL-001")


@pytest.mark.parametrize("tool,args", [
    ("delete_customer", {"customer_id": "4; DROP TABLE customers"}),
    ("delete_customer", {"customer_id": -1}),
    ("delete_customer", {}),
    ("delete_customer", {"customer_id": 4, "role": "admin"}),     # campo extra inyectado
    ("query_customers", {"search": "x" * 500}),
    ("query_customers", {"limit": 10_000}),
    ("export_all_data", {"format": "xml"}),
    ("modify_balance", {"customer_id": 1, "amount": "mucho", "reason": "x"}),
    ("create_ticket", "no-es-un-objeto"),
])
def test_invalid_args_denied(engine, tool, args):
    r = engine.evaluate("admin", tool, args)
    assert (r.decision, r.rule_id) == (DENY, "DENY-ARGS-001"), r


def test_business_condition(engine):
    ok = engine.evaluate("admin", "modify_balance", {"customer_id": 1, "amount": -5000, "reason": "ajuste"})
    big = engine.evaluate("admin", "modify_balance", {"customer_id": 1, "amount": 5000.01, "reason": "ajuste"})
    assert ok.decision == ALLOW
    assert (big.decision, big.rule_id) == (DENY, "DENY-COND-001")


def test_policy_must_be_deny_by_default():
    with pytest.raises(ValueError):
        PolicyEngine({"version": "x", "default_decision": "ALLOW", "roles": {}})
