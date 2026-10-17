"""Autenticación JWT (R1): la identidad sale de aquí, nunca del LLM."""
from __future__ import annotations

import datetime as dt

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings
from .db import connection
from .identity import AuthContext

_bearer = HTTPBearer(auto_error=False)


def authenticate(username: str, password: str) -> AuthContext | None:
    with connection() as conn:
        row = conn.execute(
            "SELECT id, username, role FROM app_users WHERE username=%s AND password_hash = crypt(%s, password_hash)",
            (username, password),
        ).fetchone()
    return AuthContext(row["id"], row["username"], row["role"]) if row else None


def issue_token(auth: AuthContext) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {"sub": str(auth.user_id), "username": auth.username, "iat": now,
               "exp": now + dt.timedelta(minutes=settings.jwt_ttl_minutes)}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def get_auth_context(cred: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> AuthContext:
    if cred is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Falta token Bearer")
    try:
        payload = jwt.decode(cred.credentials, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Token inválido: {exc}") from exc
    # El rol se lee de la BD en cada petición (fuente de verdad), no del token ni del LLM
    with connection() as conn:
        row = conn.execute("SELECT id, username, role FROM app_users WHERE id=%s", (int(payload["sub"]),)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario no existe")
    return AuthContext(row["id"], row["username"], row["role"])
