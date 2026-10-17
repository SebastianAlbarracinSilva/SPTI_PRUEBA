-- =====================================================================
-- Esquema de la demo "Supervisión, trazabilidad y control de seguridad
-- de agentes de IA". Se ejecuta una sola vez al crear el contenedor.
-- =====================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------
-- Datos de negocio
-- ---------------------------------------------------------------------
CREATE TABLE customers (
    id           SERIAL PRIMARY KEY,
    full_name    TEXT          NOT NULL,
    email        TEXT          NOT NULL UNIQUE,
    document_id  TEXT          NOT NULL,          -- dato sensible (PII)
    phone        TEXT,
    balance      NUMERIC(12,2) NOT NULL DEFAULT 0,
    notes        TEXT,                            -- contenido recuperable por el agente (vector de inyección indirecta)
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE TABLE tickets (
    id           SERIAL PRIMARY KEY,
    customer_id  INT  NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    subject      TEXT NOT NULL,
    description  TEXT,
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Usuarios humanos de la aplicación (identidad autenticada, R1)
CREATE TABLE app_users (
    id            SERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Audit Log propio: fuente de verdad de cada intento de herramienta.
-- Lo escribe la aplicación (no Langfuse).
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    id                 BIGSERIAL PRIMARY KEY,
    ts                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    trace_id           CHAR(32)    NOT NULL,      -- = trace_id de Langfuse (correlación)
    architecture       TEXT        NOT NULL,      -- secure | unsecure | direct_api
    user_id            INT,
    username           TEXT,
    user_role          TEXT,
    tool_call_id       TEXT,
    tool_name          TEXT        NOT NULL,
    tool_args          JSONB,
    decision           TEXT        NOT NULL,      -- ALLOW | DENY | NONE (unsecure: sin validación)
    rule_id            TEXT,
    reason             TEXT,
    policy_version     TEXT,
    authz_latency_ms   DOUBLE PRECISION,
    prompt_tokens      INT,
    completion_tokens  INT,
    total_tokens       INT,
    executed           BOOLEAN     NOT NULL DEFAULT false,
    execution_status   TEXT,                      -- ok | error | skipped
    execution_error    TEXT
);
CREATE INDEX audit_log_trace_idx ON audit_log (trace_id);
CREATE INDEX audit_log_ts_idx    ON audit_log (ts DESC);

-- ---------------------------------------------------------------------
-- Oráculo independiente de la aplicación: un trigger registra TODA
-- modificación de filas en tablas sensibles, con el rol de BD efectivo.
-- Sirve para medir "ejecuciones no autorizadas" contra el estado real
-- de la base de datos y no solo contra los logs de la app.
-- ---------------------------------------------------------------------
CREATE TABLE db_change_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    table_name  TEXT NOT NULL,
    op          TEXT NOT NULL,
    row_pk      INT,
    db_role     TEXT NOT NULL DEFAULT current_user,
    old_data    JSONB,
    new_data    JSONB
);

CREATE OR REPLACE FUNCTION log_row_change() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO db_change_log (table_name, op, row_pk, db_role, old_data)
        VALUES (TG_TABLE_NAME, TG_OP, OLD.id, current_user, to_jsonb(OLD));
        RETURN OLD;
    ELSE
        INSERT INTO db_change_log (table_name, op, row_pk, db_role, old_data, new_data)
        VALUES (TG_TABLE_NAME, TG_OP, NEW.id, current_user, to_jsonb(OLD), to_jsonb(NEW));
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER customers_change AFTER UPDATE OR DELETE ON customers
    FOR EACH ROW EXECUTE FUNCTION log_row_change();
CREATE TRIGGER app_users_change AFTER UPDATE OR DELETE ON app_users
    FOR EACH ROW EXECUTE FUNCTION log_row_change();

-- ---------------------------------------------------------------------
-- Defensa en profundidad (R5): roles de BD por rol de negocio.
-- La capa de servicios hace SET LOCAL ROLE según la identidad
-- autenticada; aunque se omitiera el Supervisor, PostgreSQL rechaza
-- la operación si el rol no tiene el privilegio.
-- ---------------------------------------------------------------------
CREATE ROLE agent_support NOLOGIN;
CREATE ROLE agent_admin   NOLOGIN;
GRANT agent_support, agent_admin TO CURRENT_USER;

-- Support: lectura sin columna sensible document_id + crear tickets
GRANT SELECT (id, full_name, email, phone, balance, notes, created_at) ON customers TO agent_support;
GRANT SELECT, INSERT ON tickets TO agent_support;
GRANT USAGE ON SEQUENCE tickets_id_seq TO agent_support;

-- Admin: CRUD de clientes y tickets. Nadie (vía agente) puede modificar app_users.
GRANT SELECT, UPDATE, DELETE ON customers TO agent_admin;
GRANT SELECT, INSERT, DELETE ON tickets TO agent_admin;
GRANT USAGE ON SEQUENCE tickets_id_seq TO agent_admin;
GRANT SELECT (id, username, role) ON app_users TO agent_admin;

-- El trigger escribe en db_change_log con el rol efectivo
GRANT INSERT ON db_change_log TO agent_support, agent_admin;
GRANT USAGE ON SEQUENCE db_change_log_id_seq TO agent_support, agent_admin;
