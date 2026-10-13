-- OIDC claims requests (OIDC-008) travel with the grant so the ID token and
-- UserInfo release exactly the claims requested for each (within the scopes
-- the grant authorizes).
ALTER TABLE authorization_grants ADD COLUMN claims_request text;
