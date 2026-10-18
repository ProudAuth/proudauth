// Package httpapi exposes the protocol, headless interaction, self-service, tenant
// and administration APIs over HTTP (§25, §26).
package httpapi

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/certauth"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/directory"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/hooks"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/impersonation"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/machine"
	"github.com/proudauth/proudauth/internal/maintenance"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/oauth"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/passkey"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/slots"
	"github.com/proudauth/proudauth/internal/plugin"
	"github.com/proudauth/proudauth/internal/provision"
	"github.com/proudauth/proudauth/internal/provisioning"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/registry"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/saml"
	samlidp "github.com/proudauth/proudauth/internal/saml/idp"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/ssf"
	"github.com/proudauth/proudauth/internal/token"
	"github.com/proudauth/proudauth/internal/webhooks"
	"github.com/proudauth/proudauth/internal/workflow"
	"github.com/proudauth/proudauth/internal/workload"
)

// App holds every service and the HTTP handler.
type App struct {
	// mux is the routing table Handler built; route labels come from its
	// patterns.
	mux *http.ServeMux
	D   *runtime.Deps
	// Maintenance is the operator maintenance switch (OPS-015).
	Maintenance *maintenance.Cache
	// Draining is set at shutdown so readiness fails before listeners close
	// (OPS-012).
	Draining atomic.Bool
	// forwardWarnedAt is when the last warning about X-Forwarded-For from
	// an untrusted peer was logged (Unix seconds), one a minute at most.
	forwardWarnedAt atomic.Int64
	Metrics         *observability.Metrics
	Realms          *realm.Service
	Apps            *application.Service
	Users           *identity.Service
	Authz           *authorization.Service
	Sessions        *session.Service
	Orgs            *organization.Service
	Notify          *notification.Service
	Limiter         *ratelimit.Limiter
	Auth            *authentication.Service
	Passkeys        *passkey.Service
	Federation      *federation.Service
	// SAML is the SAML identity provider profile (APP-018); SAMLKeys are the
	// realm SAML signing keys, shared with SAML connections (FED-014). Both
	// are nil unless saml.enabled.
	SAML     *samlidp.Service
	SAMLKeys *saml.Keys
	// Workload federates external workload identities (MCH-011).
	Workload *workload.Service
	// Certs holds realm certificate trust anchors (MCH-014, PROV-016).
	Certs *certauth.Service
	Hooks *hooks.Service
	// Workflows runs lifecycle workflows (EXT-015, EXT-016); Plugins manages
	// signed extension packages (EXT-014).
	Workflows *workflow.Service
	Plugins   *plugin.Service

	integrityMu sync.Mutex
	integrity   *integritySummary
	OAuth       *oauth.Service
	KeyMgr      *token.KeyManager
	Signer      *token.Signer
	Verifier    *token.Verifier
	Imp         *impersonation.Service
	Machine     *machine.Service
	// Provisioning serves SCIM to provisioning connectors (PROV-001).
	Provisioning *provisioning.Service
	// Directory integrates LDAP/AD directories and outbound SCIM
	// provisioning (PROV-010..PROV-014). With directory.enabled false it is
	// Disabled: no connector runs, but directory-sourced accounts still fail
	// closed.
	Directory *directory.Service
	// SSF is the Shared Signals Framework transmitter (AUD-016).
	SSF *ssf.Service
	// Registry is the container-registry token bridge (ADV-010).
	Registry  *registry.Bridge
	Provision *provision.Provisioner
	Features  oauth.Features
	// PolicyEval evaluates published ABAC policies after RBAC (AZ-015); nil disables.
	PolicyEval func(ctx context.Context, realmID string, subj authorization.Subject, req DecisionRequest, authTime time.Time, acr string) *Decision
	extensions []func(*http.ServeMux)
	inflight   chan struct{}
	adminSlots chan struct{}
}

// Build wires all services from shared dependencies.
func Build(d *runtime.Deps, metrics *observability.Metrics) (*App, error) {
	cfg := d.Cfg
	if metrics == nil {
		metrics = observability.NewMetrics()
	}
	a := &App{D: d, Metrics: metrics, Maintenance: &maintenance.Cache{TTL: 2 * time.Second}}
	a.Realms = realm.NewService(d)
	a.Apps = application.NewService(d)
	a.Certs = certauth.New(d)
	a.Apps.Certs = a.Certs
	a.Users = identity.NewService(d)
	a.Authz = authorization.NewService(d)
	a.Sessions = session.NewService(d)
	a.Users.Sessions = a.Sessions
	a.Notify = notification.NewService(d)
	if smtp, ok := a.Notify.Email.(*notification.SMTPSender); ok {
		smtp.Resolve = configuration.ResolveSecret
	}
	a.Orgs = organization.NewService(d, a.Authz, a.Sessions, a.Notify)
	a.Limiter = ratelimit.New(d)
	a.Orgs.Limiter = a.Limiter
	a.Orgs.RecheckPolicy = func(ctx context.Context, realmID string) organization.DomainRecheckPolicy {
		p := organization.DefaultRecheckPolicy
		if rlm, err := a.Realms.ByID(ctx, nil, realmID); err == nil {
			if d := rlm.Policy.Domains.RecheckDays; d > 0 {
				p.Interval = time.Duration(d) * 24 * time.Hour
			}
			if n := rlm.Policy.Domains.LapseAfterFailures; n > 0 {
				p.LapseAfter = n
			}
		}
		return p
	}
	policyCheck, err := credential.NewPolicy(cfg.Security.Password.MinLength, cfg.Security.Password.MaxLength, cfg.Security.Password.MaxBytes, cfg.Security.Password.BlocklistFile)
	if err != nil {
		return nil, err
	}
	hasher := &credential.Hasher{Params: credential.Params{Time: cfg.Security.Password.ArgonTime, Memory: cfg.Security.Password.ArgonMemoryKiB,
		Threads: cfg.Security.Password.ArgonThreads}, MaxBytes: cfg.Security.Password.MaxBytes, Keys: d.Keys, Pepper: len(cfg.Keys.PepperKeys) > 0,
		LegacyUntil: cfg.Security.Password.LegacyHashDeadline(), Now: d.Now, Slots: slots.New(cfg.Security.Password.HashSlots())}
	a.KeyMgr = token.NewKeyManager(d)
	a.Signer = &token.Signer{Keys: a.KeyMgr, OnFailure: func(reason string) { a.Metrics.SigningFailures.Inc(reason) }}
	a.Apps.SigningAlgorithm = a.Signer.ActiveAlgorithm
	// Security events for shared-signals receivers (AUD-016) are queued in
	// the transaction that records their audit evidence.
	a.SSF = ssf.New(d)
	a.SSF.Apps, a.SSF.Signer = a.Apps, a.Signer
	d.Audit.Hooks = append(d.Audit.Hooks, a.SSF.OnAudit)
	a.Registry = registry.New(d)
	a.Registry.Signer, a.Registry.Apps, a.Registry.Authz = a.Signer, a.Apps, a.Authz
	// Alertable security signals derived from audit evidence (OPS-004): a
	// bounded counter per signal plus a warning log line, and a distinct
	// signal when audit persistence itself fails.
	d.Audit.Observe = func(ev audit.Event, err error) {
		if err != nil {
			a.Metrics.SecuritySignals.Inc("audit_write_failed")
			d.Log.Error("audit persistence failed", "component", "audit", "event_code", ev.Type, "error", err)
			return
		}
		if sig := audit.SecuritySignal(ev); sig != "" {
			a.Metrics.SecuritySignals.Inc(sig)
			d.Log.Warn("security signal", "component", "audit", "event_code", ev.Type, "signal", sig, "outcome", ev.Outcome,
				"realm_id", ev.RealmID, "org_id", ev.OrgID, "request_id", ev.RequestID)
		}
	}
	algs := []jose.SignatureAlgorithm{}
	for _, alg := range cfg.Security.AllowedAlgorithms {
		algs = append(algs, jose.SignatureAlgorithm(alg))
	}
	a.Verifier = &token.Verifier{Keys: a.KeyMgr, Algorithms: algs, ClockSkew: cfg.Tokens.ClockSkew, MaxBytes: cfg.Limits.MaxTokenBytes, Now: d.Now}
	a.Auth = &authentication.Service{}
	*a.Auth = *authentication.NewService(d)
	a.Auth.Realms, a.Auth.Apps, a.Auth.Users, a.Auth.Sessions, a.Auth.Orgs = a.Realms, a.Apps, a.Users, a.Sessions, a.Orgs
	a.Auth.Authz, a.Auth.Notify, a.Auth.Limiter, a.Auth.Hasher, a.Auth.Policy = a.Authz, a.Notify, a.Limiter, hasher, policyCheck
	maxJSONDepth.Store(d.Cfg.Limits.MaxJSONDepth)
	a.Passkeys = passkey.New(d)
	// Operator FIDO metadata for trusted attestation (PASS-009).
	if err := a.Passkeys.LoadMetadata(cfg.WebAuthn); err != nil {
		return nil, err
	}
	a.Passkeys.CustomHosts = func(realmID string) []string { return a.Realms.VerifiedHosts(context.Background(), realmID) }
	a.Auth.Passkeys = a.Passkeys
	a.Hooks = hooks.New(d)
	a.Hooks.Observe = func(kind, outcome string) { a.Metrics.HookCalls.Inc(kind, outcome) }
	a.Auth.Hooks = a.Hooks
	// The realm's profile attribute schema (USR-007). Lookup failure yields an
	// empty schema, which rejects every self-service attribute (fail closed).
	a.Auth.Schema = func(realmID string) *identity.AttributeSchema {
		r, err := a.Realms.ByID(context.Background(), nil, realmID)
		if err != nil {
			return &identity.AttributeSchema{}
		}
		return r.Policy.AttributeSchema()
	}
	if d.Cfg.Federation.Enabled {
		a.Federation = federation.New(d)
		a.Federation.Users, a.Federation.Orgs, a.Federation.Authz = a.Users, a.Orgs, a.Authz
		if f := d.Cfg.Federation.CAFile; f != "" {
			pem, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("federation.ca_file: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("federation.ca_file: no certificates found")
			}
			a.Federation.Egress.RootCAs = pool
		}
		a.Auth.Federation = a.Federation
	}
	a.Auth.Certs = a.Certs
	a.Workload = workload.NewService(d)
	a.Workload.Apps = a.Apps
	// Issuer key sets are fetched under the federation egress rules.
	a.Workload.Egress = egress.Policy{AllowPrivate: d.Cfg.Federation.AllowPrivateNetwork, AllowCIDRs: d.Cfg.Federation.EgressAllowlist,
		RequireHTTPS: d.Cfg.Mode == "production", Timeout: d.Cfg.Federation.FetchTimeout, MaxBytes: d.Cfg.Federation.MaxResponseBytes}
	if a.Federation != nil {
		a.Workload.Egress.RootCAs = a.Federation.Egress.RootCAs
	}
	a.OAuth = oauth.NewService(d)
	a.OAuth.Hooks = a.Hooks
	a.OAuth.Workload = a.Workload
	o := a.OAuth
	o.Realms, o.Apps, o.Users, o.Sessions, o.Orgs, o.Authz, o.Auth = a.Realms, a.Apps, a.Users, a.Sessions, a.Orgs, a.Authz, a.Auth
	o.KeyMgr, o.Signer, o.Verifier, o.Limiter = a.KeyMgr, a.Signer, a.Verifier, a.Limiter
	// JWT authorization responses (JARM, ADV-002) are built by the protocol
	// layer for the authentication service's completions.
	a.Auth.AuthorizationResponse = func(ctx context.Context, realmID, clientRef, mode, redirectURI string, params map[string]string) (string, error) {
		rlm, err := a.Realms.ByID(ctx, nil, realmID)
		if err != nil {
			return "", err
		}
		c, err := a.Apps.ClientByRef(ctx, nil, realmID, clientRef)
		if err != nil {
			return "", err
		}
		return o.AuthorizationResponse(ctx, rlm, c, mode, redirectURI, params)
	}
	a.Imp = impersonation.NewService(d)
	a.Imp.Realms, a.Imp.Apps, a.Imp.Authz, a.Imp.Orgs, a.Imp.Sessions, a.Imp.OAuth, a.Imp.Notify = a.Realms, a.Apps, a.Authz, a.Orgs, a.Sessions, a.OAuth, a.Notify
	o.Impersonation = a.Imp
	a.Machine = machine.NewService(d, a.Apps, a.Orgs)
	a.Provisioning = provisioning.New(d, a.Users, a.Orgs, a.Authz, a.Sessions)
	if err := a.buildDirectory(); err != nil {
		return nil, err
	}
	a.Machine.ScopePolicy = a.OAuth.ScopesPermitted
	a.Orgs.Integrations = organization.TemplateIntegrations{
		CreateServicePrincipalTx: func(ctx context.Context, tx pgx.Tx, realmID, orgID, name, description string, actor audit.Ref) (string, error) {
			sp, err := a.Machine.CreateTx(ctx, tx, realmID, machine.SPInput{Name: name, Description: description, OwnerOrganizationID: orgID,
				AllowedOrganizationIDs: []string{orgID}}, actor)
			if err != nil {
				return "", err
			}
			return sp.ID, nil
		},
		CreateWebhookTx: func(ctx context.Context, tx pgx.Tx, realmID, orgID string, w organization.TemplateWebhook, actor audit.Ref) (string, string, error) {
			return webhooks.NewService(d).CreateTx(ctx, tx, realmID, webhooks.Input{OrganizationID: orgID, Name: w.Name, DestinationURL: w.DestinationURL,
				EventTypes: w.EventTypes, PayloadForm: w.PayloadForm}, actor)
		},
	}
	a.Provision = provision.New(d, a.Realms, a.Apps, a.Authz, a.KeyMgr, a.Users, a.Auth)
	a.Workflows = workflow.New(d, a.Authz, a.Users, a.Orgs, a.Notify, webhooks.NewService(d), a.Realms)
	// Runs that end without succeeding count as failed background work
	// (AUD-014); per-workflow detail is in GET /workflows/{id}/diagnostics.
	a.Workflows.Observe = func(kind, outcome string) {
		if kind == "run" && outcome != "succeeded" && outcome != "cancelled" {
			a.Metrics.JobsFailed.Inc("workflow")
		}
	}
	a.Plugins = plugin.New(d, a.Hooks, webhooks.NewService(d), a.Workflows, a.Authz, a.Realms)
	if cfg.SAML.Enabled {
		a.SAMLKeys = saml.NewKeys(d)
		a.SAML = samlidp.New(d, a.SAMLKeys, a.Apps, a.Auth, a.Sessions, a.Users, a.Orgs)
		if a.Federation != nil {
			federation.NewSAMLBroker(a.Federation, a.SAMLKeys)
		}
	}
	a.Features = oauth.Features{DeviceFlow: true, TokenExchange: true, PAR: true, DPoP: true, Logout: true, BackchannelLogout: true,
		MTLS: cfg.Server.MTLSListen != "" || cfg.Server.ClientCertHeader != "", MTLSOrigin: cfg.Server.MTLSOrigin}
	max := cfg.Limits.MaxInflightRequests
	if max <= 0 {
		max = 2000
	}
	a.inflight = make(chan struct{}, max)
	a.adminSlots = make(chan struct{}, max/4+1)
	return a, nil
}

// Extend registers additional routes (optional modules).
func (a *App) Extend(fn func(*http.ServeMux)) { a.extensions = append(a.extensions, fn) }

// Handler returns the public HTTP handler.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	a.routes(mux)
	a.mux = mux
	return a.middleware(a.hostPolicy(mux))
}

// hostPolicy enforces server.host_policy=strict (DEP-014): the public
// origin's host serves everything; a verified custom domain serves only its
// realm's paths; any other Host is misdirected (421). The issuer and subjects
// never depend on the host a request arrived on.
func (a *App) hostPolicy(next http.Handler) http.Handler {
	if a.D.Cfg.Server.HostPolicy != "strict" {
		return next
	}
	public := ""
	if u, err := url.Parse(a.D.Cfg.Server.PublicOrigin); err == nil {
		public = strings.ToLower(u.Hostname())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == public || isHealthPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if realmID := a.Realms.RealmForHost(r.Context(), host); realmID != "" {
			if rlm, err := a.Realms.ByID(r.Context(), nil, realmID); err == nil {
				for _, prefix := range []string{"/realms/" + rlm.Name + "/", "/api/v1/realms/" + rlm.Name + "/"} {
					if strings.HasPrefix(r.URL.Path, prefix) {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
		}
		a.writeError(w, r, problem.ErrMisdirected)
	})
}

// requestTimeout bounds request processing (NFR-001).
const requestTimeout = 30 * time.Second

// isAdminPath reports realm administration and emergency routes, which keep a
// reserved capacity slice so operators can act during overload (NFR-002).
func isAdminPath(p string) bool {
	if !strings.HasPrefix(p, "/api/v1/realms/") {
		return false
	}
	for _, seg := range []string{"/users", "/settings", "/signing-key", "/emergency/", "/sessions", "/clients", "/role-assignments"} {
		if strings.Contains(p, seg) && !strings.Contains(p, "/me/") {
			return true
		}
	}
	return false
}

func isHealthPath(p string) bool { return strings.HasPrefix(p, "/health/") }

var _ = keys.PurposeData
