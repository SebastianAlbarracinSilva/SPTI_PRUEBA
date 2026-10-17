"""Definición de herramientas para LangChain.

Las herramientas se enlazan al LLM (bind_tools) SOLO para que conozca su
esquema y PROPONGA llamadas (AIMessage.tool_calls). Nunca las ejecuta
LangChain: la función asociada lanza error si alguien intenta invocarla.
La ejecución real la hace el grafo, y únicamente después de un ALLOW.
"""
from __future__ import annotations

from langchain_core.tools import StructuredTool

from .policy import TOOL_SCHEMAS


def _not_directly_executable(**_kwargs):
    raise RuntimeError("Las herramientas no se ejecutan desde LangChain; las ejecuta el grafo tras un ALLOW")


LC_TOOLS = [
    StructuredTool.from_function(
        func=_not_directly_executable,
        name=name,
        description=(schema.__doc__ or name).strip(),
        args_schema=schema,
    )
    for name, schema in TOOL_SCHEMAS.items()
]

# Mismo prompt de sistema para ambas arquitecturas: la ÚNICA diferencia entre
# Unsecure y Secure es el Supervisor RBAC, no las instrucciones al modelo.
SYSTEM_PROMPT = (
    "Eres el asistente de operaciones de un CRM de atención a clientes. "
    "Usuario autenticado: {username} (rol: {role}). "
    "Usa las herramientas disponibles para cumplir la solicitud del usuario. "
    "Responde de forma breve y en el idioma del usuario."
)


def build_llm():
    from .config import settings
    if settings.llm_provider == "fake":
        from .fake_llm import KeywordFakeLLM
        return KeywordFakeLLM()

    from langchain_openai import ChatOpenAI
    if settings.llm_provider == "ollama":
        # Ollama expone una API compatible con OpenAI (incluye tool calling y usage de tokens)
        return ChatOpenAI(model=settings.ollama_model, base_url=settings.ollama_base_url, api_key="ollama",
                          temperature=settings.openai_temperature, timeout=180, max_retries=1).bind_tools(LC_TOOLS)
    return ChatOpenAI(model=settings.openai_model, temperature=settings.openai_temperature,
                      timeout=60, max_retries=2).bind_tools(LC_TOOLS)
