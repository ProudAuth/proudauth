# Developer entry points. Integration tests need PROUDAUTH_TEST_DATABASE_URL.
GO ?= go
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
IMAGE_NAME ?= proudauth

.PHONY: attack-suites attack-provisioning attack-federation interop-keycloak interop-zitadel build test test-unit test-e2e e2e-shard lint vet vuln sbom image dev smoke dr-drill bundle k8s-validate fuzz licenses bench bench-local bench-replicas repro-local
build:
	$(GO) build -trimpath ./...
test: vet
	$(GO) test -count=1 ./...
test-unit:
	$(GO) test -count=1 ./internal/...
test-e2e:
	$(GO) test -count=1 ./tests/...
# One shard of the end-to-end suite, as the CI e2e job runs them:
# make e2e-shard SHARD=1 SHARDS=4
SHARD ?= 0
SHARDS ?= 4
e2e-shard:
	./scripts/e2e-shard.sh $(SHARD) $(SHARDS) -count=1
vet:
	$(GO) vet ./...
lint: vet
	./scripts/check-secrets.sh
	./scripts/check-licenses.sh
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
sbom:
	$(GO) run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0 mod -licenses -json -output sbom.cdx.json
image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME):$(VERSION) .
# The development stack on an image built from this checkout.
dev:
	docker build --build-arg VERSION=dev -t proudauth:dev .
	PROUDAUTH_IMAGE=proudauth:dev docker compose -f deploy/dev/docker-compose.yaml up
smoke:
	./scripts/smoke-test.sh
# Disaster-recovery drill (DEP-019, OPS-007): standby promotion and
# point-in-time recovery with throwaway PostgreSQL containers; needs docker,
# go, curl, jq and python3. See docs/operations/backup-restore.md.
dr-drill:
	./scripts/dr-drill.sh
# Interoperability with Keycloak 26.8.0 (QA-004): ProudAuth as OpenID Provider
# and SAML identity provider for Keycloak, and Keycloak as upstream OpenID
# Provider and SAML identity provider for ProudAuth, in throwaway containers;
# needs docker, go, curl, jq, python3 and openssl. See
# docs/integrations/interoperability.md#third-party-products.
interop-keycloak:
	./scripts/interop-keycloak.sh
# Interoperability with ZITADEL v4.16.3 (QA-004, PROV-010, PROV-017): ZITADEL
# as the SCIM 2.0 service provider of ProudAuth's outbound provisioning, in
# throwaway containers; needs docker, go, curl, jq and python3. See
# docs/integrations/outbound-provisioning.md#zitadel-v4163.
interop-zitadel:
	./scripts/interop-zitadel.sh
bundle:
	IMAGE=$(IMAGE) ./scripts/offline-bundle.sh $(VERSION)
# M0/DEP-003/SEC-016: same-version Go builders on the host and cached Linux
# image; 12 release binary targets, downloads disabled, hashes only retained.
repro-local:
	./scripts/repro-local.sh
k8s-validate:
	kubectl kustomize deploy/kubernetes/overlays/example >/dev/null
fuzz:
	$(GO) test ./internal/platform/canonical -run '^$$' -fuzz '^FuzzEmail$$' -fuzztime 30s
	$(GO) test ./internal/application -run '^$$' -fuzz '^FuzzMatchRedirect$$' -fuzztime 30s
	$(GO) test ./internal/token -run '^$$' -fuzz '^FuzzRejectDuplicateKeys$$' -fuzztime 30s
	$(GO) test ./internal/authorization -run '^$$' -fuzz '^FuzzPolicyDefinition$$' -fuzztime 30s
	$(GO) test ./internal/platform/reqctx -run '^$$' -fuzz '^FuzzParseTraceparent$$' -fuzztime 15s
	$(GO) test ./internal/egress -run '^$$' -fuzz '^FuzzAllowed$$' -fuzztime 15s
	$(GO) test ./internal/application -run '^$$' -fuzz '^FuzzClaimMappings$$' -fuzztime 15s
	$(GO) test ./internal/oauth -run '^$$' -fuzz '^FuzzParseAuthorize$$' -fuzztime 15s
licenses:
	./scripts/check-licenses.sh

# Benchmarks (NFR-003..NFR-008) against a running deployment; see
# docs/operations/benchmarks.md. BENCH_URL, BENCH_REALM and
# PROUDAUTH_BENCH_ADMIN_CREDENTIALS (an identity-cli credentials file, whose
# token identity-bench refreshes) or PROUDAUTH_BENCH_ADMIN_TOKEN select the
# target. BENCH_SEED defaults to the current time so a rerun creates fresh
# objects instead of colliding with the previous run; set it to reproduce a
# dataset.
BENCH_SEED ?= $(shell date +%s)
bench:
	@if [ -z "$(BENCH_URL)" ]; then echo "make bench: set BENCH_URL to the deployment's public origin, e.g. make bench BENCH_URL=https://id.example.com" >&2; exit 2; fi
	@if [ -z "$$PROUDAUTH_BENCH_ADMIN_CREDENTIALS$$PROUDAUTH_BENCH_ADMIN_TOKEN" ]; then echo "make bench: set PROUDAUTH_BENCH_ADMIN_CREDENTIALS (identity-cli credentials file) or PROUDAUTH_BENCH_ADMIN_TOKEN (administrator token with an MFA session)" >&2; exit 2; fi
	$(GO) build -o bin/identity-bench ./cmd/identity-bench
	bin/identity-bench seed --url "$(BENCH_URL)" --realm "$(or $(BENCH_REALM),bench)" --users 10000 --orgs 500 --large 5000 --clients 20 --group-members 1000 --seed "$(BENCH_SEED)" --out bench-seed.json
	for s in client-credentials introspection password-login refresh policy audit-query mixed; do \
		bin/identity-bench run --url "$(BENCH_URL)" --seed-file bench-seed.json --scenario $$s --concurrency 32 --duration 60s --out bench-$$s.json || exit 1; \
	done
# The whole suite on this machine (NFR-003..NFR-008): a throwaway PostgreSQL
# 18 container and identity-server, identity-worker and identity-bench built
# from the checkout, the make bench dataset, every scenario and a soak run;
# results (JSON, pass criteria, CPU time, top statements) in bench-results/.
# Needs docker, go, curl, jq and python3, cached Go modules and a local
# PostgreSQL image; downloads are disabled and only resources created by
# this invocation are removed. See
# docs/operations/benchmarks.md#reference-results and the overrides at the top
# of scripts/bench-local.sh.
bench-local:
	./scripts/bench-local.sh

# Independent host processes, full make-bench cardinalities (NFR-007, NFR-008).
bench-replicas:
	BENCH_SERVER_REPLICAS=3 BENCH_SCENARIOS="refresh refresh-race" BENCH_SOAK=0 ./scripts/bench-local.sh

# Provisioning and federation attack suites (M4 exit gate,
# docs/threat-models/attack-suites.md; TestAttackSuitesExist keeps the lists
# in step with the document).
ATTACK_PROVISIONING = TestSCIMProvisioning|TestDirectoryTenantIsolation|TestDirectorySynchronization|TestSCIMAdminRaceNeverLosesChanges|TestParseFilterRejects|TestFiltersEscapeInput|TestDirectoryAuthority|TestDirectoryManagedPasswordReset|TestOutboundProvisioning|TestOutboundDeliveryClaimedOnce|TestConnectionTimeEnforcement|TestBlockedRanges|TestDirectoryErasureAndRetention
ATTACK_FEDERATION = TestFederation|TestPasswordlessLinkPurpose|TestSameSubjectFromTwoIssuers|TestFederationAdapters|TestLDAPDirectorySignIn|TestOrganizationCreationRefusesForeignConnection|TestSAMLBroker|TestSignVerifyAndWrapping|TestParserRefusals|TestSHA1Refused|TestSAMLIdentityProvider|TestRunbookConnectorCompromise|TestWorkloadFederation|TestSharedSignalsReceiver|TestFederationTransfer|TestNoCrossRealmConvergence
attack-provisioning:
	$(GO) test ./tests/e2e ./internal/provisioning ./internal/directory ./internal/egress -count=1 -run '^($(ATTACK_PROVISIONING))$$'
attack-federation:
	$(GO) test ./tests/e2e ./internal/saml -count=1 -run '^($(ATTACK_FEDERATION))$$'
attack-suites: attack-provisioning attack-federation
