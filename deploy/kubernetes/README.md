# Kubernetes manifests

Kustomize manifests for running ProudAuth on Kubernetes (DEP-013). Kubernetes is
optional; the same image runs under Docker Compose (`deploy/dev`, `deploy/prod`) or systemd.

```
deploy/kubernetes/
  base/                 server + worker Deployments, migration Job, Services,
                        PodDisruptionBudgets, NetworkPolicies, ServiceAccount
  overlays/example/     namespace, image pin, ConfigMap from config.yaml,
                        migration Secret mounted into the Job only
```

## Secure defaults

- Non-root (UID 65532), read-only root filesystem, all capabilities dropped,
  `RuntimeDefault` seccomp, no service-account token (the IdP never calls the
  Kubernetes API).
- Secrets are referenced, never generated or embedded: create `proudauth-secrets`
  out of band with keys `database_url`, `root_key_v1` (and any other `file:`
  references in your config). The config uses `file:/run/secrets/...` refs.
- The example overlay separates database roles (OPS-013,
  [installation.md](../../docs/operations/installation.md#database-roles)):
  `database_url` in `proudauth-secrets` is the runtime role's connection
  (`storage.runtime_role: proudauth_app`), and a second Secret,
  `proudauth-migration-secrets` with key `migration_database_url` (the schema
  owner's connection), is mounted at `/run/migration-secrets` into the
  migration Job only (`overlays/example/migrate-job-secrets.yaml`). Create
  both roles before the Job first runs: it connects as the runtime role too,
  and its grants to `runtime_role` fail when that role does not exist. Keep
  `storage.migrate_on_start` off, since the server and worker cannot read the
  owner's connection. The base mounts only `proudauth-secrets`; an overlay
  without separate roles leaves out the patch and the two `storage` keys.
- `/health/live` is a process check; `/health/ready` fails when the database,
  schema version, active signing keys or clock agreement are unsafe, removing the
  pod from traffic without restarting it. At shutdown it reports `draining` for
  `server.drain_delay` (default 5 s) before the listeners close, so keep
  `terminationGracePeriodSeconds` above `drain_delay + shutdown_deadline`.
- The liveness, startup and readiness probes use the internal listener (port
  `internal`, `:9090`), which has no load shedding. On `:8080` the health
  routes share the reserved request pool with administrators, and a full pool
  would answer liveness with `503` and restart pods mid-incident. The probes
  need `server.internal_listen: ":9090"` (as in the example configuration),
  not the default `127.0.0.1:9090`; custom overlays should point their probes
  at port `internal` too. The NetworkPolicy does not list the kubelet, as for
  the worker's probes on `:9091`; if your network plugin filters probe traffic
  from the node, allow it to port 9090.
- Metrics, status and the health checks listen on `:9090`, exposed only through
  the `proudauth-internal` Service and allowed only from the `monitoring`
  namespace.
- The NetworkPolicies allow egress to the database (5432), and for workers to
  SMTP (587, 465), at any address; `base/networkpolicy.yaml` has commented
  `to:` examples that restrict them to your database and SMTP relay.
- Workers serve `/health/live`, `/health/ready`, `/metrics` and `/status` on
  `workers.metrics_listen` (`:9091` in the example configuration); the worker's
  liveness and startup probes use it, so keep it set.

## Rollout procedure (DEP-012)

1. Back up the database and export the revocation log
   (`identity-cli revocation-log`), see `docs/operations/`.
2. Run the migration Job for the new version and wait for completion. Migrations
   in a release are expand-only; old pods keep working against the new schema.
   Kubernetes stops the Job after `activeDeadlineSeconds: 3600`, retries
   included. Keep it above `storage.migration_statement_timeout` (default
   `10m` per statement) times the number of long statements one run may
   contain, such as concurrent index builds, and raise both together for
   large tables
   ([upgrades.md](../../docs/operations/upgrades.md#no-transaction-migrations)).
3. Update the image of `proudauth-server` and `proudauth-worker` (rolling,
   `maxUnavailable: 0`).
4. Contract migrations (dropping old columns) ship only in a later release, after
   every pod runs a version that no longer reads them.

```bash
# A Job's pod template cannot change in place: remove the previous version's
# migration Job (kept for an hour after it finishes) before applying.
kubectl -n proudauth delete job proudauth-migrate --ignore-not-found
kubectl apply -k deploy/kubernetes/overlays/example
kubectl -n proudauth wait --for=condition=complete job/proudauth-migrate
kubectl -n proudauth rollout status deploy/proudauth-server
```

Bootstrap the first administrator from a one-off pod with the CLI
(`identity-cli realm-create` then `identity-cli bootstrap`); the setup token is
printed once and expires.

Validate the rendered manifests before applying:

```bash
kubectl kustomize deploy/kubernetes/overlays/example | kubectl apply --dry-run=server -f -
```
