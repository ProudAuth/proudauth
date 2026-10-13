# Install ProudAuth with Docker Compose

Run your own identity API, background worker and PostgreSQL database. This
installation uses prebuilt images: no Go compiler or source checkout is required.
ProudAuth supplies identity APIs; your application supplies its sign-in interface.

Requirements: Docker Engine/Desktop, Docker Compose v2 with `--wait`, POSIX `sh`,
Python 3.9+ and available ports. The release image selects `linux/amd64` or
`linux/arm64` automatically. Version `0.2.0-alpha.1` is a pre-release; no external
security review or conformance certification has been completed.

## Download and verify

Download `proudauth-v0.2.0-alpha.1-compose.tar.gz` and `SHA256SUMS` from
[GitHub Releases](https://github.com/proudbase/proudauth/releases/tag/v0.2.0-alpha.1).
Verify the archive's line from `SHA256SUMS` before extracting it. For example,
with the GitHub CLI already installed:

```sh
gh release download v0.2.0-alpha.1 --repo proudbase/proudauth \
  --pattern 'proudauth-v0.2.0-alpha.1-compose.tar.gz' --pattern SHA256SUMS
python3 - <<'PY'
import hashlib, pathlib
name = 'proudauth-v0.2.0-alpha.1-compose.tar.gz'
lines = pathlib.Path('SHA256SUMS').read_text().splitlines()
expected = next(line.split()[0] for line in lines if line.split()[-1].lstrip('*') == name)
assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == expected, 'checksum mismatch'
print('Archive checksum verified')
PY
tar -xzf proudauth-v0.2.0-alpha.1-compose.tar.gz
cd proudauth-v0.2.0-alpha.1-compose
```

The archive contains `docker-compose.yaml`, both example environment profiles,
the initializer, database setup script and this guide. Keep these files in one
directory. Checksums establish integrity against the downloaded manifest;
release provenance is described in the service's installation runbook.

## Pull the image

The GitHub Container Registry package is the default registry:

```sh
docker pull ghcr.io/proudbase/proudauth:0.2.0-alpha.1
```

The Docker Hub mirror uses the maintainer's Docker Hub namespace:

```sh
docker pull mohamadalialghanem/proudauth:0.2.0-alpha.1
```

Set `PROUDAUTH_IMAGE=docker.io/mohamadalialghanem/proudauth:0.2.0-alpha.1`
in `.env` to use that mirror. Use the immutable release digest for a controlled
deployment after verifying it against the release's image manifest.
Check registry availability and the published digests on the release page.

The image includes `/usr/local/bin/identity-server`, `identity-worker` and
`identity-cli`. It runs as UID/GID 65532 with a read-only filesystem. You can
inspect the server's flags without starting a database:

```sh
docker run --rm ghcr.io/proudbase/proudauth:0.2.0-alpha.1 -help
```

The server and worker require PostgreSQL and durable encryption keys, so use
the supplied Compose file to run the complete service.

## Local evaluation

```sh
./init.sh demo
# Edit .env if ports 8080 or 9090 are already occupied.
# When changing PUBLIC_PORT, also change PROUDAUTH_PUBLIC_ORIGIN to match it.
./init.sh demo
docker compose config --quiet
docker compose pull
docker compose up -d --wait
docker compose ps
PA_ORIGIN=$(python3 -c 'import json; print(json.load(open("config.yaml"))["server"]["public_origin"])')
curl --fail "$PA_ORIGIN/health/ready"
```

This profile uses HTTP, development cookies and a private development email
sink. It is restricted to loopback. The database has no host port. Operator
port 9090 is bound to `127.0.0.1` in every profile. Do not tunnel or publish
the demo operator listener or development mailbox.

Create your realm once, then bootstrap its first administrator:

```sh
docker compose exec server /usr/local/bin/identity-cli realm-create -name main
docker compose exec server /usr/local/bin/identity-cli bootstrap \
  -realm main -email admin@example.test -username root-admin
```

With the default public port **8080**, complete setup inside the server
container as follows. For any other public port, use the host CLI instructions
below instead; keep its URL equal to the canonical origin from `.env`.

```sh
docker compose exec server /usr/local/bin/identity-cli setup-account \
  --url "$PA_ORIGIN" --realm main
docker compose exec server /usr/local/bin/identity-cli login \
  --url "$PA_ORIGIN" --realm main
```

Keep the printed one-time setup token private. The setup command asks for it
and a new password; there is no default administrator password. First sign-in
uses the bootstrap username `root-admin`; the email becomes a sign-in
identifier only after verification. Sign-in requires TOTP enrollment and an
email verification code. Store recovery codes
offline. For the demo, read your verification messages only from the host's
private operator mailbox at
`http://127.0.0.1:9090/dev/mailbox?realm=main&recipient=admin@example.test`.
The mailbox is a development tool and is absent in production.

The initial realm creates a CLI client and signing key. Discovery becomes
available at `http://localhost:8080/realms/main/.well-known/openid-configuration`.
`realm-create` and `bootstrap` are one-time operator actions; repeating either
on an initialized realm is refused. Ordinary restarts preserve the realm.

## Nondefault local ports

For example, these settings use host ports 18080 and 19090:

```dotenv
PUBLIC_PORT=18080
OPERATOR_PORT=19090
PROUDAUTH_PUBLIC_ORIGIN=http://localhost:18080
```

Choose these ports and origin in `.env` **before** `realm-create` and bootstrap;
run `./init.sh demo` and start the stack. Changing the public origin does not
rewrite an existing realm's issuer. For a different origin after creating a
realm, use a fresh demo installation directory and unique Compose project name.
The server still listens on **8080 inside its container**. A CLI run there cannot
reach its own loopback port 18080; switching its URL to 8080 would derive a
different administrator resource audience from the realm's stored issuer.
Run the released CLI **on the host** for setup and login, using the exact
canonical origin. Operator commands `realm-create` and `bootstrap` still run
inside the server container as above.

The release provides `identity-cli_linux_amd64`, `identity-cli_linux_arm64`,
`identity-cli_darwin_amd64` and `identity-cli_darwin_arm64`. These commands choose
your Linux/macOS asset, download it and verify its checksum before execution:

```sh
case "$(uname -s)" in Linux) PA_CLI_OS=linux;; Darwin) PA_CLI_OS=darwin;; *) echo 'Use Linux/macOS, or WSL2 on Windows'; exit 1;; esac
case "$(uname -m)" in x86_64|amd64) PA_CLI_ARCH=amd64;; arm64|aarch64) PA_CLI_ARCH=arm64;; *) echo 'Unsupported architecture'; exit 1;; esac
PA_CLI_ASSET="identity-cli_${PA_CLI_OS}_${PA_CLI_ARCH}"
PA_RELEASE_URL=https://github.com/proudbase/proudauth/releases/download/v0.2.0-alpha.1
curl --fail --location --output "$PA_CLI_ASSET" "$PA_RELEASE_URL/$PA_CLI_ASSET"
curl --fail --location --output RELEASE_SHA256SUMS "$PA_RELEASE_URL/SHA256SUMS"
python3 - "$PA_CLI_ASSET" <<'PY'
import hashlib, pathlib, sys
name = sys.argv[1]
lines = pathlib.Path('RELEASE_SHA256SUMS').read_text().splitlines()
expected = next(line.split()[0] for line in lines if line.split()[-1].lstrip('*') == name)
assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == expected, 'CLI checksum mismatch'
print('CLI checksum verified')
PY
chmod 700 "$PA_CLI_ASSET"
PA_ORIGIN=$(python3 -c 'import json; print(json.load(open("config.yaml"))["server"]["public_origin"])')
"./$PA_CLI_ASSET" setup-account --url "$PA_ORIGIN" --realm main
"./$PA_CLI_ASSET" login --url "$PA_ORIGIN" --realm main
curl --fail "$PA_ORIGIN/health/ready"
```

Use your configured realm name instead of `main` when changed. For this
example, verification email is at the **host's** private operator mailbox:
`http://127.0.0.1:19090/dev/mailbox?realm=main&recipient=admin@example.test`.
Use your configured `OPERATOR_PORT` in that URL. Host CLI credentials are stored
with mode 0600 in your user configuration directory; keep them private.

## Production configuration

Use a fresh installation directory, choose your issuer before creating a
realm, and arrange an HTTPS reverse proxy and SMTP relay. Start with:

```sh
cp .env.example .env
chmod 600 .env
# Edit .env: your HTTPS public origin, SMTP_HOST, SMTP_USERNAME and EMAIL_FROM.
./init.sh production
```

If SMTP authentication is configured, the initializer creates the private
secret directory and asks for your SMTP password. Write it without putting it
in shell history or `.env`:

```sh
python3 - <<'PY'
import getpass, os, pathlib
path = pathlib.Path('secrets/smtp_password')
path.chmod(0o600)
try:
    path.write_text(getpass.getpass('SMTP password: '))
finally:
    path.chmod(0o444)
PY
./init.sh production
docker compose config --quiet
docker compose pull
docker compose up -d --wait
docker compose exec server /usr/local/bin/identity-cli doctor
```

The generated production configuration requires HTTPS, Secure cookies, SMTP
with `starttls` or `implicit` TLS, strict host checks and file-backed secrets.
It disables support impersonation and migration-on-start. JSON syntax in
`config.yaml` is valid YAML; it safely quotes operator-provided values.

Terminate TLS at your reverse proxy and forward only the public listener to
`127.0.0.1:8080`. Preserve the canonical `Host` header. Set
`PROUDAUTH_TRUSTED_PROXIES` to the exact address/CIDR of the proxy as observed
by the container; remove attacker-supplied forwarding headers at the proxy.
Leave it empty when no forwarding headers are needed. Never trust all addresses.
For a remote proxy, firewall access to the host and change `PUBLIC_BIND` only
to the intended private interface. Port 9090 and PostgreSQL stay private.

Bootstrap a real administrator using the same commands as above with your
realm name and email address, then run `setup-account` and `login` against
**your** HTTPS origin, for example `https://identity.your-domain.com`.
For browser authorization, create the realm with
`-login-ui-url https://app.your-domain.com/login` or configure that URL later.
ProudAuth's project website is documentation, not a hosted identity endpoint.

See [ENVIRONMENT.md](ENVIRONMENT.md) for every `.env` setting and secret file.

## Database roles, keys and upgrades

PostgreSQL 18.6 is pinned by default, with `shared_buffers=128MB` and
`max_connections=100`. The server and worker each allow 20 pooled connections.
These are single-machine starter settings, not capacity guarantees.
PostgreSQL 18's data volume is mounted at `/var/lib/postgresql`.

The database initializer creates `proudauth_owner` and `proudauth_app`. Only
the one-shot migration service receives the owner's DSN. The server and worker
use the runtime role, which receives data privileges without schema ownership,
role creation or the ability to disable audit triggers. `doctor` should report
`database role proudauth_app: data privileges only` (OPS-013).

`init.sh` preserves existing keys and passwords, and refuses mismatched DSNs.
Keep the root key with a separately protected backup. Losing the key makes
encrypted signing material unusable; generating a new key is not recovery.
Changing a password file does not rotate a PostgreSQL password already stored
in a persistent database. Use an explicit database/key rotation procedure.

For a new version, take and verify a database/key backup, review its migration
plan, then update the version or digest in `.env`:

```sh
./init.sh
docker compose pull
docker compose run --rm migrate -plan
# Use -backup-reference <your-verified-backup-id> for a contract migration.
docker compose run --rm migrate -backup-reference <your-verified-backup-id>
docker compose up -d --wait
docker compose exec server /usr/local/bin/identity-cli doctor
```

This starter Compose deployment is a single node. It does not implement
database HA, TLS termination, backups, secret rotation or disaster recovery
for you. Production operation requires the service's installation,
backup/restore, key-custody and upgrade runbooks.

## Stop and inspect

```sh
docker compose ps
docker compose logs --tail=100 server worker
docker compose down
```

`down` keeps the database volume. **`docker compose down -v` permanently
deletes this installation's identity data.** Do not copy credentials, mailbox
responses or logs containing sensitive operational data into issue reports.

The standalone `docker-deploy/` source folder is a separate offline local
demonstration, including Swagger. The release installer intentionally exposes
only the identity API and the private operator listener.
