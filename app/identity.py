"""Identidad autenticada (R1).

AuthContext se construye EXCLUSIVAMENTE en FastAPI a partir de un JWT
validado y del registro del usuario en BD. Es inmutable (frozen) y el LLM
nunca lo recibe ni lo produce: los argumentos de las herramientas no
contienen user_id ni rol.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthContext:
    user_id: int
    username: str
    role: str
