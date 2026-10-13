# 0002. Implementation language and libraries: Go

**Status:** Accepted

## Context

docs/plan.md §37.1 proposes a Go reference implementation and requires a separate
decision naming the toolchain and vetted protocol and cryptography libraries.
ARC-009 forbids custom cryptographic primitives.

## Decision

- **Language/toolchain:** Go 1.27. `go.mod` declares the minimum (`go 1.27.1`,
  no `toolchain` line); the Dockerfile build stage pins a patch release
  (`golang:1.27.2-trixie`), and CI and the release workflow use the latest 1.27
  patch release at run time (`go-version: "1.27.x"`, `check-latest: true`), so
  standard-library security fixes reach builds without a `go.mod` change.
  Binaries are built with
  `CGO_ENABLED=0 -trimpath` and shipped in `gcr.io/distroless/static-debian12:nonroot`.
- **HTTP:** standard library `net/http` with method-and-pattern `ServeMux`; no web
  framework.
- **Libraries in use:**

  | Purpose | Library |
  | --- | --- |
  | PostgreSQL driver and pool | `github.com/jackc/pgx/v5` |
  | JOSE / JWT signing and verification | `github.com/go-jose/go-jose/v4` |
  | Password hashing (Argon2id) | `golang.org/x/crypto/argon2` |
  | TOTP / HOTP codes | `github.com/pquerna/otp` |
  | Identifier generation (ULID) | `github.com/oklog/ulid/v2` |
  | Configuration parsing | `gopkg.in/yaml.v3` (unknown keys rejected) |
  | Unicode normalization, IDNA | `golang.org/x/text`, `golang.org/x/net/idna` |
  | CLI password prompt | `golang.org/x/term` |
  | WebAuthn ceremonies | `github.com/go-webauthn/webauthn` |

- **Standard-library cryptography:** AES-256-GCM (`crypto/aes`, `crypto/cipher`),
  HKDF-SHA256 (`crypto/hkdf`), HMAC-SHA256, SHA-256 digests, `crypto/rand`, and
  RSA (3072-bit), ECDSA P-256 and Ed25519 key generation.

## Alternatives considered

- **Rust or Java/Kotlin**: viable; rejected for this reference implementation in
  favor of Go's static binaries, standard-library TLS/crypto and the spec's
  suggested layout.
- **An ORM**: rejected; SQL is written explicitly so tenant predicates, locks
  (`FOR UPDATE`, advisory locks) and transaction boundaries stay reviewable.
- **A JWT library other than go-jose** (for example `golang-jwt`): go-jose was
  chosen for JWK/JWKS handling and algorithm allowlisting in one library.

## Consequences

- No CGO: no system OpenSSL; FIPS-validated builds are not provided.
- New dependencies must pass `scripts/check-licenses.sh` and be added to `NOTICE`.

## Migration implications

Changing a cryptographic library must keep the stored formats readable: PHC
Argon2id verifiers, the keyring ciphertext layout
(`0x01 | version | nonce | sealed`), and PKCS#8-wrapped signing keys
(see [0015](0015-key-hierarchy.md)).

## Related requirement IDs

ARC-009, DEP-003, SEC-016, GOV-007, §5.1, §36.1, §37.1
