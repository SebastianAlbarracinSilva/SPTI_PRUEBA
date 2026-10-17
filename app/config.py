"""Configuración centralizada (variables de entorno / .env)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "postgresql://spti:spti@localhost:5432/spti")
    jwt_secret: str = os.getenv("JWT_SECRET", "cambia-este-secreto-en-produccion-0123456789")
    jwt_ttl_minutes: int = int(os.getenv("JWT_TTL_MINUTES", "120"))

    # openai | ollama (local, gratis) | fake (solo ensayos offline, ver app/fake_llm.py)
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai").strip().lower()
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    openai_temperature: float = float(os.getenv("OPENAI_TEMPERATURE", "0"))
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")

    policy_path: Path = Path(os.getenv("POLICY_PATH", str(ROOT / "app" / "policy.yaml")))
    # Presupuesto del Supervisor: si la decisión tarda más, fail-closed (R3/R7)
    authz_timeout_ms: float = float(os.getenv("AUTHZ_TIMEOUT_MS", "50"))
    # Comportamiento tras DENY: "terminate" (recomendado) o "feedback"
    deny_mode: str = os.getenv("DENY_MODE", "terminate")
    max_agent_steps: int = int(os.getenv("MAX_AGENT_STEPS", "6"))

    langfuse_enabled: bool = (_bool("LANGFUSE_ENABLED", True)
                              and os.getenv("LANGFUSE_PUBLIC_KEY", "").startswith("pk-lf-"))
    demo_mode: bool = _bool("DEMO_MODE", True)
    log_file: Path = Path(os.getenv("LOG_FILE", str(ROOT / "logs" / "app.jsonl")))

    @property
    def model_name(self) -> str:
        return {"ollama": self.ollama_model, "fake": "fake"}.get(self.llm_provider, self.openai_model)


settings = Settings()
