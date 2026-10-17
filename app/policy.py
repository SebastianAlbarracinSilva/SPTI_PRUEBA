"""Motor de política RBAC: puro, determinista y sin LLM.

- Deny-by-default (R2): rol o herramienta no listados => DENY.
- Validación de argumentos (R4): esquema Pydantic estricto por herramienta
  + condiciones de negocio declaradas en policy.yaml.

Lo usan tanto el Supervisor (nodo de LangGraph) como la capa de servicios
(re-verificación, R5), por lo que ambas capas aplican la MISMA política.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

ALLOW = "ALLOW"
DENY = "DENY"


# ---------------------------------------------------------------------
# Esquemas de argumentos (R4). extra="forbid": un campo inesperado (p. ej.
# "role" o "user_id" inyectado por el LLM) invalida la llamada.
# ---------------------------------------------------------------------
class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class QueryCustomersArgs(_Args):
    """Busca clientes por nombre o email."""
    search: str = Field("", max_length=100, description="Texto a buscar en nombre o email; vacío = todos")
    limit: int = Field(10, ge=1, le=50, description="Máximo de resultados (1-50)")


class CreateTicketArgs(_Args):
    """Crea un ticket de soporte para un cliente."""
    customer_id: int = Field(..., gt=0, description="ID del cliente")
    subject: str = Field(..., min_length=3, max_length=200)
    description: str = Field("", max_length=2000)


class DeleteCustomerArgs(_Args):
    """Elimina definitivamente un cliente."""
    customer_id: int = Field(..., gt=0, description="ID del cliente")


class ModifyBalanceArgs(_Args):
    """Suma (o resta, si es negativo) un monto al saldo de un cliente."""
    customer_id: int = Field(..., gt=0)
    amount: float = Field(..., ge=-1_000_000, le=1_000_000, description="Monto a sumar (negativo para restar)")
    reason: str = Field(..., min_length=3, max_length=300)


class ExportAllDataArgs(_Args):
    """Exporta TODOS los datos de clientes (incluye datos sensibles)."""
    format: Literal["json", "csv"] = "json"


class ChangeAgentRoleArgs(_Args):
    """Cambia el rol de un usuario de la aplicación."""
    username: str = Field(..., min_length=1, max_length=50)
    new_role: str = Field(..., min_length=1, max_length=30)


TOOL_SCHEMAS: dict[str, type[_Args]] = {
    "query_customers": QueryCustomersArgs,
    "create_ticket": CreateTicketArgs,
    "delete_customer": DeleteCustomerArgs,
    "modify_balance": ModifyBalanceArgs,
    "export_all_data": ExportAllDataArgs,
    "change_agent_role": ChangeAgentRoleArgs,
}


# ---------------------------------------------------------------------
# Resultado de una evaluación
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class PolicyResult:
    decision: str            # ALLOW | DENY
    rule_id: str
    reason: str
    args: dict[str, Any] | None = None   # argumentos normalizados (solo si ALLOW)


@dataclass
class Rule:
    tool: str
    rule_id: str
    conditions: list[dict[str, Any]] = field(default_factory=list)


_OPS = {
    "lte": lambda v, ref: v <= ref,
    "gte": lambda v, ref: v >= ref,
    "abs_lte": lambda v, ref: abs(v) <= ref,
    "in": lambda v, ref: v in ref,
}


class PolicyEngine:
    def __init__(self, raw: dict[str, Any]):
        if str(raw.get("default_decision", DENY)).upper() != DENY:
            raise ValueError("La política debe ser deny-by-default")
        self.version: str = str(raw["version"])
        self.roles: dict[str, dict[str, Rule]] = {
            role: {r["tool"]: Rule(r["tool"], r["rule_id"], r.get("conditions") or []) for r in rules or []}
            for role, rules in (raw.get("roles") or {}).items()
        }
        self.forbidden: dict[str, str] = {f["tool"]: f["rule_id"] for f in raw.get("forbidden_tools") or []}
        self.rate_limit: dict[str, int] = raw.get("rate_limit") or {}
        for role, rules in self.roles.items():
            for tool, rule in rules.items():
                for c in rule.conditions:
                    if c.get("op") not in _OPS:
                        raise ValueError(f"Operador desconocido en {rule.rule_id}: {c}")

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyEngine":
        with open(path, encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    def evaluate(self, role: str | None, tool_name: str, args: Any) -> PolicyResult:
        # 1) Herramienta inexistente => deny-by-default
        if tool_name not in TOOL_SCHEMAS:
            return PolicyResult(DENY, "DENY-TOOL-001", f"Herramienta no registrada: {tool_name!r}")
        # 2) Herramienta prohibida para todos los roles vía agente
        if tool_name in self.forbidden:
            return PolicyResult(DENY, self.forbidden[tool_name], f"{tool_name} está prohibida vía agente para todos los roles")
        # 3) Rol desconocido => deny-by-default
        if not role or role not in self.roles:
            return PolicyResult(DENY, "DENY-ROLE-001", f"Rol no definido en la política: {role!r}")
        # 4) Rol sin permiso sobre la herramienta
        rule = self.roles[role].get(tool_name)
        if rule is None:
            return PolicyResult(DENY, "DENY-RBAC-001", f"El rol {role!r} no tiene permiso para {tool_name}")
        # 5) Validación de argumentos (tipos, rangos, formato)
        if not isinstance(args, dict):
            return PolicyResult(DENY, "DENY-ARGS-001", "Los argumentos deben ser un objeto JSON")
        try:
            parsed = TOOL_SCHEMAS[tool_name].model_validate(args)
        except ValidationError as exc:
            errs = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
            return PolicyResult(DENY, "DENY-ARGS-001", f"Argumentos inválidos: {errs}")
        normalized = parsed.model_dump()
        # 6) Condiciones de negocio de la regla
        for cond in rule.conditions:
            value = normalized.get(cond["field"])
            if value is None or not _OPS[cond["op"]](value, cond["value"]):
                return PolicyResult(
                    DENY, "DENY-COND-001",
                    f"Condición {cond['field']} {cond['op']} {cond['value']} no se cumple ({rule.rule_id})",
                )
        return PolicyResult(ALLOW, rule.rule_id, f"Permitido por {rule.rule_id}", normalized)
