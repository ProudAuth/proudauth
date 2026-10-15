# Deploy ProudAuth

One image, configured only by environment variables. `dev/` and `prod/` each
have two files: `docker-compose.yaml` and `.env`. Both `.env` files have the
same variables; only the values differ.

| Folder | Contains | For |
| --- | --- | --- |
| [`dev/`](dev/) | ProudAuth, PostgreSQL, Mailpit (fake mail) and Swagger UI | Your machine |
| [`prod/`](prod/) | ProudAuth only; packaged as each release's Compose installer | A server with your PostgreSQL, HTTPS proxy and SMTP |
| [`kubernetes/`](kubernetes/) | Kustomize base and example overlay | Kubernetes |

## Development

```sh
cd deploy/dev
docker compose up -d --wait
```

Nothing to fill in: it runs the released image named in `.env`. `make dev` from
the repository root builds this checkout as `proudauth:dev` and runs the same
stack on it; CI runs `make smoke` against the image it builds.

| URL | Purpose |
| --- | --- |
| http://localhost:8080 | Identity API |
| http://localhost:8080/realms/main/.well-known/openid-configuration | Discovery |
| http://localhost:8025 | Every email sent (verification codes, invitations) |
| http://localhost:8081 | Swagger UI |
| http://127.0.0.1:9090/status | Operator status |

`docker compose down` stops it and keeps the data; `docker compose down -v`
deletes the data.

## Production

On the server, outside any Git checkout:

```sh
mkdir proudauth && cd proudauth
curl -fsSLO https://raw.githubusercontent.com/proudauth/proudauth/v0.2.0-alpha.4/deploy/prod/docker-compose.yaml
curl -fsSLO https://raw.githubusercontent.com/proudauth/proudauth/v0.2.0-alpha.4/deploy/prod/.env
# Fill every empty value in .env (the root key: openssl rand -hex 32), then:
chmod 600 .env
docker compose pull
docker compose up -d
```

The committed `prod/.env` stays an empty template (`TestDeployDevAndProd`).

Compose refuses to start while a required value is missing, and the image
refuses development settings in production. Point your HTTPS reverse proxy
at `PUBLIC_BIND:PUBLIC_PORT`, forwarding the original `Host` header.

Back up `PROUDAUTH_ROOT_KEY` with the database: without it, the stored keys
cannot be read. `PROUDAUTH_PUBLIC_ORIGIN` becomes the realm's issuer when the
realm is first created; changing it later does not move an existing realm.

## Both

Every start runs migrations and creates the `main` realm if it is missing; the
second start changes nothing. Create the first administrator once:

```sh
docker compose exec server identity-cli bootstrap -realm main -email you@example.com -username owner
docker compose exec server identity-cli setup-account --url <PROUDAUTH_PUBLIC_ORIGIN> --realm main
docker compose exec server identity-cli login --url <PROUDAUTH_PUBLIC_ORIGIN> --realm main
```

The first sign-in enrolls an authenticator app (TOTP) and verifies the email
address; in development the code arrives in Mailpit. Every variable is
described in [configuration](../docs/operations/configuration.md#environment-overrides).
