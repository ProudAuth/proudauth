-- SuperTokens -> ProudAuth export (format proudauth.supertokens-export.v1).
-- Tested with SuperTokens core 12.0.7 and the PostgreSQL plugin 9.5.5.
-- Read-only (one REPEATABLE READ, READ ONLY transaction). Run it with psql
-- against the SuperTokens core database, once per app, and pass the core
-- version (core_version in the core's version.yaml):
--   psql "$SUPERTOKENS_DB" -X -A -t -q -v app_id=public -v core_version=12.0.7 \
--     -f supertokens-export.sql > supertokens-export.json
-- The output holds password hashes and TOTP secrets: write it to a protected
-- location and delete it after the migration (MIG-015).
-- "users" uses the SuperTokens bulk-import user shape (externalUserId,
-- userMetadata, userRoles, totpDevices, loginMethods) plus supertokensUserId;
-- WebAuthn login methods are listed with recipeId "webauthn" so they are
-- reported, not dropped.
\set ON_ERROR_STOP on
\set QUIET on
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH
app AS (SELECT :'app_id'::text AS id),
recipe AS (
  -- every recipe user with the primary user it belongs to
  SELECT DISTINCT ON (a.user_id) a.user_id AS recipe_user_id, a.primary_or_recipe_user_id AS primary_id,
         a.is_linked_or_is_a_primary_user AS linked, a.recipe_id, a.time_joined
  FROM all_auth_recipe_users a, app WHERE a.app_id = app.id
  ORDER BY a.user_id
),
-- the ID the application sees: the external ID when a user ID mapping exists
visible AS (
  SELECT r.primary_id, coalesce(m.external_user_id, r.primary_id) AS app_user_id
  FROM (SELECT DISTINCT primary_id FROM recipe) r
  LEFT JOIN userid_mapping m ON m.app_id = (SELECT id FROM app) AND m.supertokens_user_id = r.primary_id
),
login AS (
  SELECT r.primary_id, r.recipe_user_id,
    jsonb_strip_nulls(jsonb_build_object(
      'recipeId', r.recipe_id,
      'tenantIds', (SELECT coalesce(jsonb_agg(DISTINCT t.tenant_id), '["public"]'::jsonb) FROM recipe_user_tenants t
                    WHERE t.app_id = (SELECT id FROM app) AND t.recipe_user_id = r.recipe_user_id),
      'isPrimary', r.linked AND r.recipe_user_id = r.primary_id,
      'timeJoinedInMSSinceEpoch', r.time_joined,
      'email', coalesce(ep.email, tp.email, pl.email, wa.email),
      'isVerified', EXISTS (SELECT 1 FROM emailverification_verified_emails v
                    WHERE v.app_id = (SELECT id FROM app) AND v.user_id IN (r.recipe_user_id, coalesce(mr.external_user_id, r.recipe_user_id))
                      AND v.email = coalesce(ep.email, tp.email, pl.email, wa.email)),
      'passwordHash', ep.password_hash,
      'hashingAlgorithm', CASE WHEN ep.password_hash LIKE '$2%' THEN 'BCRYPT' WHEN ep.password_hash LIKE '$argon2%' THEN 'ARGON2'
                               WHEN ep.password_hash LIKE '$f_scrypt$%' THEN 'FIREBASE_SCRYPT' END,
      'thirdPartyId', tp.third_party_id,
      'thirdPartyUserId', tp.third_party_user_id,
      'phoneNumber', pl.phone_number,
      'rpId', wa.rp_id,
      'webauthnCredentialIds', (SELECT jsonb_agg(c.id ORDER BY c.created_at) FROM webauthn_credentials c
                    WHERE c.app_id = (SELECT id FROM app) AND c.user_id = wa.user_id)
    )) AS j
  FROM recipe r
  LEFT JOIN userid_mapping mr ON mr.app_id = (SELECT id FROM app) AND mr.supertokens_user_id = r.recipe_user_id
  LEFT JOIN emailpassword_users ep ON ep.app_id = (SELECT id FROM app) AND ep.user_id = r.recipe_user_id
  LEFT JOIN thirdparty_users tp ON tp.app_id = (SELECT id FROM app) AND tp.user_id = r.recipe_user_id
  LEFT JOIN passwordless_users pl ON pl.app_id = (SELECT id FROM app) AND pl.user_id = r.recipe_user_id
  LEFT JOIN webauthn_users wa ON wa.app_id = (SELECT id FROM app) AND wa.user_id = r.recipe_user_id
),
users AS (
  SELECT v.primary_id, jsonb_strip_nulls(jsonb_build_object(
    'supertokensUserId', v.primary_id,
    'externalUserId', CASE WHEN v.app_user_id <> v.primary_id THEN v.app_user_id END,
    'userMetadata', (SELECT um.user_metadata::jsonb FROM user_metadata um WHERE um.app_id = (SELECT id FROM app) AND um.user_id = v.app_user_id),
    'userRoles', (SELECT jsonb_agg(jsonb_build_object('role', ur.role, 'tenantIds', ur.tenants) ORDER BY ur.role)
                  FROM (SELECT role, jsonb_agg(DISTINCT tenant_id) AS tenants FROM user_roles
                        WHERE app_id = (SELECT id FROM app) AND user_id = v.app_user_id GROUP BY role) ur),
    'totpDevices', (SELECT jsonb_agg(jsonb_build_object('deviceName', d.device_name, 'secretKey', d.secret_key, 'period', d.period, 'skew', d.skew) ORDER BY d.device_name)
                  FROM totp_user_devices d WHERE d.app_id = (SELECT id FROM app) AND d.user_id = v.app_user_id AND d.verified),
    'loginMethods', (SELECT jsonb_agg(l.j ORDER BY (l.j->>'timeJoinedInMSSinceEpoch')::bigint, l.recipe_user_id) FROM login l WHERE l.primary_id = v.primary_id)
  )) AS j
  FROM visible v
)
SELECT jsonb_pretty(jsonb_build_object(
  'format', 'proudauth.supertokens-export.v1',
  'supertokens', jsonb_build_object('core_version', :'core_version', 'plugin', 'postgresql', 'app_id', (SELECT id FROM app),
                                     'exported_at', to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
  'tenants', (SELECT coalesce(jsonb_agg(jsonb_build_object('tenantId', t.tenant_id) ORDER BY t.tenant_id), '[]'::jsonb)
              FROM tenants t WHERE t.app_id = (SELECT id FROM app)),
  'roles', (SELECT coalesce(jsonb_agg(jsonb_build_object('role', ro.role, 'permissions',
              (SELECT coalesce(jsonb_agg(rp.permission ORDER BY rp.permission), '[]'::jsonb) FROM role_permissions rp
               WHERE rp.app_id = ro.app_id AND rp.role = ro.role)) ORDER BY ro.role), '[]'::jsonb)
            FROM roles ro WHERE ro.app_id = (SELECT id FROM app)),
  'users', (SELECT coalesce(jsonb_agg(u.j ORDER BY u.primary_id), '[]'::jsonb) FROM users u)
));
COMMIT;
