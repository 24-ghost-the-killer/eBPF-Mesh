-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Least privilege and Row Level Security (spec section 10, ADR 0016).
--
-- The API serves requests as `sentinel_api`: not the table owner, no
-- BYPASSRLS, so every policy below applies to it. Each request runs in a
-- transaction that sets app.user_id / app.tenant_id / app.key_tenant /
-- app.is_admin with set_config(..., true). The application checks the
-- membership role first; RLS is the second safety net and does not trust
-- the tenant id alone (it comes from the URL): the user must be a member
-- of it, or a database-verified API key must belong to it (app_tenant_ok).

-- Roles are cluster-wide: tolerate a concurrent migration of another
-- database creating it first (check-then-create would race).
DO $$
BEGIN
  CREATE ROLE sentinel_api NOLOGIN;              -- deployment grants LOGIN + password
EXCEPTION WHEN duplicate_object OR unique_violation THEN
  NULL;
END $$;

CREATE FUNCTION app_tenant() RETURNS BIGINT LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.tenant_id', true), '')::bigint $$;
CREATE FUNCTION app_user() RETURNS BIGINT LANGUAGE sql STABLE AS
  $$ SELECT nullif(current_setting('app.user_id', true), '')::bigint $$;
CREATE FUNCTION app_admin() RETURNS BOOLEAN LANGUAGE sql STABLE AS
  $$ SELECT coalesce(current_setting('app.is_admin', true), '') = 'on' $$;

-- True when the request may act in app_tenant(): platform admin, a member,
-- or an API key of that tenant. SECURITY DEFINER: reads memberships
-- without RLS (no policy recursion).
CREATE FUNCTION app_tenant_ok() RETURNS BOOLEAN LANGUAGE sql STABLE
  SECURITY DEFINER SET search_path = public AS $$
  SELECT app_tenant() IS NOT NULL AND (
       app_admin()
    OR app_tenant() = nullif(current_setting('app.key_tenant', true), '')::bigint
    OR EXISTS (SELECT 1 FROM memberships m
               WHERE m.user_id = app_user() AND m.tenant_id = app_tenant()))
$$;

-- Signup creates a tenant and its first owner in one transaction.
CREATE FUNCTION tenant_has_members(t BIGINT) RETURNS BOOLEAN LANGUAGE sql STABLE
  SECURITY DEFINER SET search_path = public AS
  $$ SELECT EXISTS (SELECT 1 FROM memberships WHERE tenant_id = t) $$;

GRANT USAGE ON SCHEMA public TO sentinel_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_api;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO sentinel_api;
GRANT EXECUTE ON FUNCTION app_tenant(), app_user(), app_admin(), app_tenant_ok(),
  tenant_has_members(BIGINT) TO sentinel_api;

-- Tenant data: only the tenant of the current request (or a platform admin).
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenants_access ON tenants TO sentinel_api
  USING ((id = app_tenant() AND app_tenant_ok()) OR app_admin()
         OR EXISTS (SELECT 1 FROM memberships m WHERE m.tenant_id = tenants.id AND m.user_id = app_user()))
  WITH CHECK (true);

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY memberships_access ON memberships TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR user_id = app_user() OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin()
              -- bootstrap: the first owner of a brand-new tenant is its creator
              OR (tenant_id = app_tenant() AND user_id = app_user() AND role = 'owner'
                  AND NOT tenant_has_members(tenant_id)));

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY assets_access ON assets TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());

-- policies has no tenant_id; it is reachable only through a visible asset.
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY policies_access ON policies TO sentinel_api
  USING (EXISTS (SELECT 1 FROM assets a WHERE a.id = policies.asset_id))
  WITH CHECK (EXISTS (SELECT 1 FROM assets a WHERE a.id = policies.asset_id));

-- Global rules (tenant_id NULL) are platform-admin only.
ALTER TABLE rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY rules_access ON rules TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());

ALTER TABLE tenant_rules_version ENABLE ROW LEVEL SECURITY;
CREATE POLICY trv_access ON tenant_rules_version TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());

ALTER TABLE attacks ENABLE ROW LEVEL SECURITY;
CREATE POLICY attacks_access ON attacks TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());

-- API keys are looked up by hash before the tenant is known: the lookup
-- runs through api_key_lookup() (SECURITY DEFINER), everything else is RLS.
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY api_keys_access ON api_keys TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());

CREATE FUNCTION api_key_lookup(hash TEXT)
  RETURNS TABLE (id BIGINT, tenant_id BIGINT, scopes TEXT[], created_by BIGINT)
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
    UPDATE api_keys SET last_used = now() WHERE key_hash = hash
    RETURNING id, tenant_id, scopes, created_by
  $$;
REVOKE ALL ON FUNCTION api_key_lookup(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION api_key_lookup(TEXT) TO sentinel_api;

-- Allocating a protected IP must avoid every tenant's prefixes, which RLS
-- hides; this exposes the prefixes only (no owner, no origin).
CREATE FUNCTION used_protected_prefixes() RETURNS SETOF CIDR
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS
  $$ SELECT protected_prefix FROM assets $$;
REVOKE ALL ON FUNCTION used_protected_prefixes() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION used_protected_prefixes() TO sentinel_api;

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY webhooks_access ON webhooks TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin())
  WITH CHECK ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());

-- Audit: tenants read their own entries; anyone may append, nobody edits.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_log FOR SELECT TO sentinel_api
  USING ((tenant_id = app_tenant() AND app_tenant_ok()) OR app_admin());
CREATE POLICY audit_append ON audit_log FOR INSERT TO sentinel_api WITH CHECK (true);
REVOKE UPDATE, DELETE ON audit_log FROM sentinel_api;
