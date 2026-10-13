#!/usr/bin/env python3
"""Generate literal YAML/JSON configuration and private stable file secrets.

Uses only Python's standard library. Never sources .env, interpolates values,
executes operators' strings, downloads dependencies, or prints secret contents.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent


def fail(message):
    raise ValueError(message)


def read_env(path):
    values = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f".env line {number}: expected NAME=value")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            fail(f".env line {number}: invalid or duplicate variable")
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                fail(f".env line {number}: unmatched quote")
            value = value[1:-1]
        elif "#" in value or value != value.strip():
            fail(f".env line {number}: quote values containing spaces or #")
        if "$" in value or "`" in value or "\x00" in value:
            fail(f".env line {number}: values must be literal, without interpolation")
        values[key] = value
    return values


def safe_path(path):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        fail(f"{path.name}: expected a regular file, not a symlink or directory")


def write_file(path, data, mode):
    safe_path(path)
    data = data.encode()
    if path.exists() and path.read_bytes() == data:
        path.chmod(mode)
        return
    handle, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as output:
            output.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def init(arguments):
    if len(arguments) > 1 or (arguments and arguments[0] not in ("demo", "production")):
        fail("usage: ./init.sh [production|demo]")
    requested = arguments[0] if arguments else None
    env_path = ROOT / ".env"
    safe_path(env_path)
    if not env_path.exists():
        example = ".env.demo.example" if requested == "demo" else ".env.example"
        write_file(env_path, (ROOT / example).read_text(), 0o600)
        print("Created private .env from " + example + ".")
    env_path.chmod(0o600)
    defaults = read_env(ROOT / ".env.example")
    supplied = read_env(env_path)
    unknown = set(supplied) - set(defaults)
    if unknown:
        fail("Unknown .env variables: " + ", ".join(sorted(unknown)))
    values = defaults | supplied
    profile = values["DEPLOYMENT_PROFILE"]
    if profile not in ("demo", "production") or (requested and profile != requested):
        fail("DEPLOYMENT_PROFILE must match the requested demo or production profile")
    origin = urlsplit(values["PROUDAUTH_PUBLIC_ORIGIN"])
    if (origin.scheme not in ("http", "https") or not origin.hostname or origin.username
            or origin.password or origin.path not in ("", "/") or origin.query or origin.fragment):
        fail("PROUDAUTH_PUBLIC_ORIGIN must be an absolute HTTP(S) origin without credentials or path")
    if profile == "production" and (origin.scheme != "https" or origin.hostname.endswith(".example.com")):
        fail("Production requires your own HTTPS PROUDAUTH_PUBLIC_ORIGIN; replace identity.example.com")
    if profile == "demo" and origin.hostname not in ("localhost", "127.0.0.1", "::1"):
        fail("The demo profile is limited to a loopback public origin")
    if profile == "demo" and values["PUBLIC_BIND"] not in ("127.0.0.1", "::1"):
        fail("The demo profile must bind PUBLIC_BIND to loopback")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", values["COMPOSE_PROJECT_NAME"]):
        fail("COMPOSE_PROJECT_NAME must contain lowercase letters, digits, underscores or dashes")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", values["PROUDAUTH_REALM"]):
        fail("PROUDAUTH_REALM must contain lowercase letters, digits, underscores or dashes")
    ipaddress.ip_address(values["PUBLIC_BIND"])
    for name in ("PROUDAUTH_IMAGE", "POSTGRES_IMAGE"):
        if not re.fullmatch(r"[A-Za-z0-9_./:@-]+", values[name]):
            fail(name + " must be a literal container image reference")
        if ":" not in values[name] or values[name].endswith(":latest"):
            fail(name + " must use an explicit version tag or digest")
    def integer(name, lower, upper):
        if not re.fullmatch(r"[0-9]+", values[name]):
            fail(name + " must be an integer")
        result = int(values[name])
        if not lower <= result <= upper:
            fail(f"{name} must be between {lower} and {upper}")
        return result
    public_port = integer("PUBLIC_PORT", 1, 65535)
    integer("OPERATOR_PORT", 1, 65535)
    if profile == "demo" and (origin.port or (443 if origin.scheme == "https" else 80)) != public_port:
        fail("Demo PROUDAUTH_PUBLIC_ORIGIN port must match PUBLIC_PORT")
    if values["PUBLIC_PORT"] == values["OPERATOR_PORT"]:
        fail("PUBLIC_PORT and OPERATOR_PORT must differ")
    postgres_max = integer("POSTGRES_MAX_CONNECTIONS", 30, 1000)
    pool_max = integer("POOL_MAX_CONNECTIONS", 2, 200)
    if pool_max * 3 + 10 > postgres_max:
        fail("POSTGRES_MAX_CONNECTIONS must leave room for server, worker, migrations and operator connections")
    if not re.fullmatch(r"[1-9][0-9]*(kB|MB|GB)", values["POSTGRES_SHARED_BUFFERS"]):
        fail("POSTGRES_SHARED_BUFFERS must be a positive PostgreSQL size, for example 128MB")
    proxies = [item.strip() for item in values["PROUDAUTH_TRUSTED_PROXIES"].split(",") if item.strip()]
    for proxy in proxies:
        if ipaddress.ip_network(proxy, strict=False).prefixlen == 0:
            fail("PROUDAUTH_TRUSTED_PROXIES must not trust every address")
    smtp_port = integer("SMTP_PORT", 1, 65535)
    if values["SMTP_TLS"] not in ("starttls", "implicit"):
        fail("SMTP_TLS must be starttls or implicit")
    if values["LOG_LEVEL"] not in ("info", "warn", "error"):
        fail("LOG_LEVEL must be info, warn or error")
    if profile == "production":
        if not values["SMTP_HOST"] or values["SMTP_HOST"].endswith(".example.com"):
            fail("Production requires your SMTP_HOST; replace smtp.example.com")
        if "@" not in values["EMAIL_FROM"] or values["EMAIL_FROM"].endswith("@example.com"):
            fail("Production requires your EMAIL_FROM address")
    secret_dir = ROOT / "secrets"
    if secret_dir.is_symlink() or (secret_dir.exists() and not secret_dir.is_dir()):
        fail("secrets must be a private directory, not a symlink")
    secret_dir.mkdir(mode=0o700, exist_ok=True)
    secret_dir.chmod(0o700)
    generated = {}
    for name, count in (("root_key", 32), ("postgres_password", 24), ("owner_password", 24),
                        ("app_password", 24), ("metrics_token", 32)):
        path = secret_dir / name
        safe_path(path)
        value = path.read_text() if path.exists() else secrets.token_hex(count)
        if not re.fullmatch(r"[0-9a-fA-F]{" + str(count * 2) + "}", value):
            fail(name + ": existing secret must have its original hexadecimal length; it was not replaced")
        write_file(path, value, 0o444)
        generated[name] = value
    for filename, role, password in (("database_url", "proudauth_app", "app_password"),
                                     ("owner_database_url", "proudauth_owner", "owner_password")):
        dsn = f"postgres://{role}:{generated[password]}@postgres:5432/proudauth?sslmode=disable"
        path = secret_dir / filename
        safe_path(path)
        if path.exists() and path.read_text() != dsn:
            fail(filename + ": existing DSN differs; explicit database credential rotation is required")
        write_file(path, dsn, 0o444)
    smtp_path = secret_dir / "smtp_password"
    safe_path(smtp_path)
    if not smtp_path.exists():
        write_file(smtp_path, "", 0o444)
    smtp_path.chmod(0o444)
    if profile == "production" and values["SMTP_USERNAME"] and not smtp_path.read_text().strip():
        fail("Write your SMTP password to secrets/smtp_password (no trailing newline), then rerun ./init.sh; other secrets were preserved")
    config = {
        "mode": "development" if profile == "demo" else "production",
        "server": {"public_listen": ":8080", "internal_listen": ":9090",
                   "public_origin": values["PROUDAUTH_PUBLIC_ORIGIN"].rstrip("/"), "host_policy": "strict",
                   "trusted_proxies": proxies, "metrics_token": "file:/run/secrets/metrics_token"},
        "identity": {"default_realm": values["PROUDAUTH_REALM"]},
        "storage": {"database_url": "file:/run/secrets/database_url", "runtime_role": "proudauth_app",
                    "max_conns": pool_max, "statement_timeout": "10s", "migrate_on_start": False},
        "keys": {"root_keys": [{"version": 1, "ref": "file:/run/secrets/root_key"}], "active_version": 1},
        "sessions": {"cookie_insecure_dev": profile == "demo", "cookie_same_site": "lax"},
        "delivery": {"email": {"adapter": "dev_sink" if profile == "demo" else "smtp",
                               "smtp_host": values["SMTP_HOST"], "smtp_port": smtp_port,
                               "smtp_tls": values["SMTP_TLS"], "smtp_username": values["SMTP_USERNAME"],
                               "smtp_password": "file:/run/secrets/smtp_password", "from": values["EMAIL_FROM"]}},
        "impersonation": {"enabled": False},
        "observability": {"log_format": "json", "log_level": values["LOG_LEVEL"]},
        "privacy": {"telemetry_opt_in": False},
    }
    # JSON is valid YAML and quotes every operator-provided value safely.
    write_file(ROOT / "config.yaml", json.dumps(config, indent=2) + "\n", 0o444)
    print("Configured " + profile + "; .env is private and existing keys/passwords were preserved.")
    print("Run docker compose config --quiet, docker compose pull, then docker compose up -d --wait.")


if __name__ == "__main__":
    lock = ROOT / ".configure.lock"
    acquired = False
    try:
        lock.mkdir(mode=0o700)
        acquired = True
        init(sys.argv[1:])
    except (ValueError, OSError) as error:
        # Exception text never contains operator values or secret file contents.
        print("Configuration failed: " + str(error), file=sys.stderr)
        sys.exit(1)
    finally:
        if acquired:
            lock.rmdir()
