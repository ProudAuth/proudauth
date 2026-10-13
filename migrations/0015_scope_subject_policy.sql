-- Subject policy for scopes (TOK-008): a scope may require the subject to hold
-- permissions in the token's organization (or realm) context. Tokens never
-- carry a scope whose required permissions the subject lacks at issuance,
-- including on refresh.
ALTER TABLE scopes ADD COLUMN required_permissions text[] NOT NULL DEFAULT '{}';
