-- Postgres-true Row-Level Security for the Agent Studio tables.
--
-- Apply manually after `init_db()` creates the tables (the SQLite dev
-- path doesn't need it; tenant isolation is enforced at the
-- application layer by the `scoped()` helper in db_models.py).
--
-- Usage:
--   1. Switch DATABASE_URL to a postgres:// URL
--   2. Run init_db() (or `alembic upgrade head` once we have alembic)
--   3. Run this file:  psql $DATABASE_URL -f RLS_POSTGRES.sql
--   4. Set `app.current_customer_id` per request via a middleware:
--        await db.execute(text("SET LOCAL app.current_customer_id = :cid"),
--                         {"cid": customer["customer_id"]})
--
-- The session variable is bind-aware: writes from one tenant cannot
-- leak into another tenant's rows even if a bug skips the app-layer
-- `scoped()` filter.

-- ── Customers (only their own row) ──────────────────────────────────
ALTER TABLE agent_studio_customers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS customer_self_select ON agent_studio_customers;
CREATE POLICY customer_self_select ON agent_studio_customers
    FOR ALL
    USING (
        customer_id = current_setting('app.current_customer_id', true)
        OR current_setting('app.role', true) = 'admin'
    );

-- ── API keys (only the customer's own) ──────────────────────────────
ALTER TABLE agent_studio_api_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_key_self ON agent_studio_api_keys;
CREATE POLICY api_key_self ON agent_studio_api_keys
    FOR ALL
    USING (
        customer_id = current_setting('app.current_customer_id', true)
        OR current_setting('app.role', true) = 'admin'
    );

-- ── Admin grants (admin-only by design) ─────────────────────────────
ALTER TABLE agent_studio_admin_grants ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_grant_admin_only ON agent_studio_admin_grants;
CREATE POLICY admin_grant_admin_only ON agent_studio_admin_grants
    FOR ALL
    USING (
        current_setting('app.role', true) = 'admin'
        OR customer_id = current_setting('app.current_customer_id', true)
    );

-- ── Deployments (the highest-cardinality tenant table) ──────────────
ALTER TABLE agent_studio_deployments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS deployment_self ON agent_studio_deployments;
CREATE POLICY deployment_self ON agent_studio_deployments
    FOR ALL
    USING (
        customer_id = current_setting('app.current_customer_id', true)
        OR current_setting('app.role', true) = 'admin'
    );

-- ── Sessions + messages ─────────────────────────────────────────────
ALTER TABLE agent_studio_sessions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS session_self ON agent_studio_sessions;
CREATE POLICY session_self ON agent_studio_sessions
    FOR ALL
    USING (
        customer_id = current_setting('app.current_customer_id', true)
        OR current_setting('app.role', true) = 'admin'
    );

ALTER TABLE agent_studio_session_messages ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS session_msg_via_session ON agent_studio_session_messages;
CREATE POLICY session_msg_via_session ON agent_studio_session_messages
    FOR ALL
    USING (
        EXISTS (
            SELECT 1 FROM agent_studio_sessions s
            WHERE s.session_id = agent_studio_session_messages.session_id
              AND (s.customer_id = current_setting('app.current_customer_id', true)
                   OR current_setting('app.role', true) = 'admin')
        )
    );

-- ── Eval / red-team / supply-chain histories ────────────────────────
-- Legacy rows from the JSON-file era have customer_id IS NULL; readable
-- by admin only. New rows MUST stamp customer_id from the API layer.
ALTER TABLE agent_studio_eval_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS eval_self ON agent_studio_eval_runs;
CREATE POLICY eval_self ON agent_studio_eval_runs
    FOR ALL
    USING (
        (customer_id IS NOT NULL
         AND customer_id = current_setting('app.current_customer_id', true))
        OR current_setting('app.role', true) = 'admin'
    );

ALTER TABLE agent_studio_red_team_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rt_self ON agent_studio_red_team_runs;
CREATE POLICY rt_self ON agent_studio_red_team_runs
    FOR ALL
    USING (
        (customer_id IS NOT NULL
         AND customer_id = current_setting('app.current_customer_id', true))
        OR current_setting('app.role', true) = 'admin'
    );

ALTER TABLE agent_studio_supply_chain_scans ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sc_self ON agent_studio_supply_chain_scans;
CREATE POLICY sc_self ON agent_studio_supply_chain_scans
    FOR ALL
    USING (
        (customer_id IS NOT NULL
         AND customer_id = current_setting('app.current_customer_id', true))
        OR current_setting('app.role', true) = 'admin'
    );

-- ── Sanity: confirm the policies actually load ─────────────────────
-- SELECT policyname, tablename FROM pg_policies WHERE tablename LIKE 'agent_studio_%';
