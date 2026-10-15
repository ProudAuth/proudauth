# Run ProudAuth with Docker Compose

One image, configured only by environment variables. Each folder has two
files: `docker-compose.yaml` and `.env`. Both `.env` files have the same
variables; only the values differ.

| Folder | Contains | For |
| --- | --- | --- |
| [`dev/`](dev/) | ProudAuth, PostgreSQL, Mailpit (fake mail) and Swagger UI | Your machine |
| [`prod/`](prod/) | ProudAuth only | A server with your PostgreSQL, HTTPS proxy and SMTP |

## Development

```sh
cd docker-deploy/dev
docker compose up -d --build --wait
```

Nothing to fill in. `--build` builds the image from this checkout; set
`PROUDAUTH_IMAGE` in `.env` to a release tag to run a published image instead.

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

1. Copy `prod/` to the server, outside any Git checkout.
2. Fill every empty value in `.env` (`chmod 600 .env`). The root key is
   `openssl rand -hex 32`.
3. `docker compose up -d --wait`

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
docker compose exec server identity-cli bootstrap -realm main -email you@example.com -username admin
docker compose exec server identity-cli setup-account --url <PROUDAUTH_PUBLIC_ORIGIN> --realm main
docker compose exec server identity-cli login --url <PROUDAUTH_PUBLIC_ORIGIN> --realm main
```

The first sign-in enrolls an authenticator app (TOTP) and verifies the email
address; in development the code arrives in Mailpit. Every variable is
described in [configuration](../docs/operations/configuration.md#environment-overrides).
