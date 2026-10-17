# SPTI — Supervisión, trazabilidad y control de seguridad de agentes de IA

Demo comparativa de dos arquitecturas de agente con herramientas sobre PostgreSQL:

- **Unsecure:** el LLM interpreta la solicitud e invoca las herramientas directamente.
- **Secure:** el LLM (LangChain) **propone**; LangGraph intercepta la llamada; un **Supervisor RBAC determinista** decide ALLOW o DENY; la decisión queda en un **Audit Log** propio; solo con ALLOW se ejecuta. **Langfuse solo observa.**

```
FastAPI (JWT) ─► LangGraph: agent ─► supervisor_rbac ─► tools ─► services (re-check + SET ROLE) ─► PostgreSQL
                                          │                                           
                                          ├─► audit_log (síncrono, fuente de verdad)
                                          └─► Langfuse (asíncrono, no bloqueante)
```

## Documentación

| Documento | Contenido |
|---|---|
| [docs/01_matriz_de_controles.md](docs/01_matriz_de_controles.md) | 5 vectores de riesgo (OWASP LLM 2025) y Matriz de Controles |
| [docs/02_arquitectura_secure.md](docs/02_arquitectura_secure.md) | Flujo, estado y grafo de LangGraph, comportamiento tras DENY, Langfuse, latencia, trazabilidad R1–R7 |
| [docs/03_plan_de_pruebas.md](docs/03_plan_de_pruebas.md) | Plan de pruebas IEEE: T01–T07, B01, métricas y amenazas a la validez |
| [docs/04_guion_video_demo.md](docs/04_guion_video_demo.md) | Guion del video de 5 min (con marcadores para datos reales) |

## Puesta en marcha (Windows)

Requisitos: Docker Desktop, Python 3.11 (`py -3.11`), [Ollama](https://ollama.com) con `ollama pull qwen2.5:7b` (gratis, local) y claves de Langfuse Cloud (gratis). Opcional: `LLM_PROVIDER=openai` + `OPENAI_API_KEY`.

```powershell
# 1. Base de datos (crea esquema, roles de BD y datos semilla)
docker compose up -d

# 2. Entorno Python
py -3.11 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt

# 3. Configuración
copy .env.example .env      # y completa LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY, LANGFUSE_HOST

# 4. Servidor
.\.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Abre **http://localhost:8000**. Desde ahí eliges el usuario (`soporte1` o `admin1`) y la arquitectura (Unsecure o Secure), usas los prompts predefinidos T01–T07 y ves en vivo la tabla `customers`, el Audit Log y el oráculo `db_change_log`. Swagger está en `/docs`.

| Usuario | Contraseña | Rol |
|---|---|---|
| soporte1 | soporte123 | support |
| soporte2 | soporte123 | support |
| admin1 | admin123 | admin |

## Pruebas y métricas

```powershell
.\.venv\Scripts\python -m pytest -q                    # 51 pruebas deterministas (sin LLM; incluye BD real)
.\.venv\Scripts\python scripts\bench_authz.py          # B01: p50/p95/p99 de la autorización
.\.venv\Scripts\python scripts\run_scenarios.py        # T01–T07 × N=10 × 2 arquitecturas con el LLM real
.\.venv\Scripts\python scripts\run_scenarios.py --runs 3 --only T02 T05 --arch secure
```

Los resultados se guardan en `reports/` (Markdown + JSON). Para ensayar sin OpenAI existe `LLM_PROVIDER=fake`, un LLM simulado por palabras clave que obedece cualquier inyección. **Sus resultados no sirven como evidencia.**

## Estructura

```
app/
  policy.yaml        política RBAC (deny-by-default, condiciones, rate limit)
  policy.py          motor de políticas + esquemas Pydantic de argumentos
  supervisor.py      Supervisor: fail-closed, timeout, lockout (T05), latencia
  agent_secure.py    grafo LangGraph: agent → supervisor_rbac → tools / deny_handler
  agent_unsecure.py  agente sin control (línea base)
  services.py        ejecución de herramientas: re-verificación + SET LOCAL ROLE (R5)
  audit.py           Audit Log en PostgreSQL
  telemetry.py       Langfuse v3 asíncrono (solo observabilidad)
  auth.py            JWT → AuthContext (identidad confiable)
  main.py            API FastAPI + endpoints de demo
  static/index.html  interfaz de la demo
db/                  esquema, roles de BD, trigger oráculo, datos semilla
scripts/             escenarios, benchmark B01
tests/               pytest
```

## Endpoints principales

| Método | Ruta | Uso |
|---|---|---|
| POST | `/auth/login` | Obtiene el JWT |
| POST | `/api/chat` | `{message, architecture: secure\|unsecure, session_id?}` → respuesta, `trace_id`, decisiones, URL de Langfuse |
| POST | `/api/tools/{tool}` | Llama a la capa de servicios **sin** LangGraph (demuestra R5) |
| GET | `/api/metrics` | Agregados del Audit Log |
| GET/POST | `/api/demo/state`, `/api/demo/reset`, `/api/demo/audit/{trace_id}` | Solo con `DEMO_MODE=true` |
