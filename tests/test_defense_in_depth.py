"""R5: aunque se omita el nodo de LangGraph, la capa de servicios y PostgreSQL
siguen impidiendo la acción. Requiere `docker compose up -d`."""
import psycopg
import pytest

from app import db
from app.services import PermissionDeniedError, execute_secure
from tests.conftest import ADMIN, SUPPORT


@pytest.fixture(autouse=True)
def _db():
    try:
        db.reset_seed()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"PostgreSQL no disponible: {exc}")
    yield
    db.reset_seed()


def _count(sql, *args):
    with db.connection() as conn:
        return list(conn.execute(sql, args).fetchone().values())[0]


def test_service_rechecks_policy_without_graph(engine):
    before = _count("SELECT count(*) FROM customers")
    with pytest.raises(PermissionDeniedError) as exc:
        execute_secure(engine, SUPPORT, "delete_customer", {"customer_id": 3})
    assert exc.value.rule_id == "DENY-RBAC-001"
    assert _count("SELECT count(*) FROM customers") == before


def test_postgres_role_blocks_even_if_app_checks_are_bypassed():
    """Tercera barrera: con SET ROLE agent_support, DELETE/UPDATE fallan en la propia BD."""
    for sql in ("DELETE FROM customers WHERE id=3",
                "UPDATE app_users SET role='admin' WHERE username='soporte1'",
                "SELECT document_id FROM customers"):
        with db.connection() as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute("SET LOCAL ROLE agent_support")
                    conn.execute(sql)


def test_admin_cannot_change_roles_even_at_db_level():
    with db.connection() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("SET LOCAL ROLE agent_admin")
                conn.execute("UPDATE app_users SET role='admin' WHERE username='soporte1'")


def test_support_allowed_paths_work(engine):
    r = execute_secure(engine, SUPPORT, "query_customers", {"search": "Ana"})
    assert r["count"] == 1 and "document_id" not in r["customers"][0]
    t = execute_secure(engine, SUPPORT, "create_ticket", {"customer_id": 1, "subject": "Prueba T01"})
    assert t["status"] == "created"


def test_admin_delete_is_logged_by_db_oracle(engine):
    start = _count("SELECT coalesce(max(id),0) FROM db_change_log")
    execute_secure(engine, ADMIN, "delete_customer", {"customer_id": 4})
    with db.connection() as conn:
        rows = conn.execute("SELECT op, row_pk, db_role FROM db_change_log WHERE id > %s AND table_name='customers'",
                            (start,)).fetchall()
    assert rows == [{"op": "DELETE", "row_pk": 4, "db_role": "agent_admin"}]
