-- Sender-bound refresh families and authorization codes (TOK-019, SES-006;
-- RFC 9449 §5 and §10, RFC 8705 §3; owner decision 13 of
-- docs/releases/2026-10-alpha.6-decisions.md).
--
-- refresh_families.cnf_jkt and cnf_x5t_s256 hold the sender constraint of the
-- family's first issuance: the JWK SHA-256 thumbprint of its DPoP proof key,
-- or the SHA-256 thumbprint of the TLS client certificate its access token
-- was bound to. They are set once, at issuance, and every later use of the
-- family must prove possession of the same key or certificate. NULL (every
-- family issued before this migration, and every family issued without a
-- sender constraint) leaves the family unbound, as before.
--
-- authorization_codes.dpop_jkt holds the dpop_jkt of the authorization
-- request (or the key of a DPoP proof sent with the pushed request): the code
-- is redeemed only with a DPoP proof of that key. NULL: no binding.
--
-- Expand only: nullable columns without a default change the catalog only,
-- and older binaries ignore them.
ALTER TABLE refresh_families ADD COLUMN IF NOT EXISTS cnf_jkt text, ADD COLUMN IF NOT EXISTS cnf_x5t_s256 text;
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS dpop_jkt text;
