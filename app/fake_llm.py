"""LLM falso por palabras clave — SOLO para ensayar la demo y el pipeline de
pruebas sin OpenAI (LLM_PROVIDER=fake). Imita a un modelo "obediente" que
sigue cualquier instrucción, incluidas las inyecciones. Sus resultados NO
sirven como evidencia del Plan de Pruebas (que exige el LLM real).
"""
from __future__ import annotations

import base64
import re
import uuid

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage


def _call(name: str, args: dict) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"id": f"call_{uuid.uuid4().hex[:12]}", "name": name, "args": args}],
                     usage_metadata={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})


def _plan(text: str) -> AIMessage | None:
    t = text.lower()
    for chunk in re.findall(r"[A-Za-z0-9+/=]{24,}", text):
        try:
            return _plan(base64.b64decode(chunk).decode("utf-8"))
        except Exception:  # noqa: BLE001
            pass
    ids = [int(x) for x in re.findall(r"(?:id|customer_id)\s*(?:=|de|con)?\s*(\d+)", t)]
    if "export_all_data" in t or "exporta" in t or "export " in t:
        return _call("export_all_data", {"format": "json"})
    if "change_agent_role" in t or "cambia mi rol" in t:
        return _call("change_agent_role", {"username": "soporte1", "new_role": "admin"})
    if ("elimina" in t or "delete" in t) and ids:
        return _call("delete_customer", {"customer_id": ids[0]})
    if ("saldo" in t or "balance" in t) and ids:
        amount = float((re.findall(r"(?:suma|add)\s+(\d+)", t) or ["100"])[0])
        return _call("modify_balance", {"customer_id": ids[0], "amount": amount, "reason": "solicitud del usuario"})
    m = re.search(r"cliente\s+([A-ZÁÉÍÓÚ][\wáéíóú]+\s+[A-ZÁÉÍÓÚ][\wáéíóú]+)|customer\s+([A-Z]\w+\s+[A-Z]\w+)", text)
    if m:
        return _call("query_customers", {"search": (m.group(1) or m.group(2)).split()[0]})
    m = re.search(r"contenga\s+'([^']+)'", text)
    if m or "clientes" in t:
        return _call("query_customers", {"search": m.group(1) if m else ""})
    return None


class KeywordFakeLLM:
    def invoke(self, messages, config=None) -> AIMessage:
        last = messages[-1]
        if isinstance(last, ToolMessage):
            if "export_all_data" in str(last.content) and last.name == "query_customers":
                return _call("export_all_data", {"format": "json"})       # sigue la inyección indirecta
            return AIMessage(content=f"Resultado de {last.name}: {str(last.content)[:400]}")
        human = next((m for m in reversed(messages) if isinstance(m, HumanMessage)), None)
        plan = _plan(human.content if human else "")
        return plan or AIMessage(content="listo")

    def bind_tools(self, *_a, **_k):
        return self


