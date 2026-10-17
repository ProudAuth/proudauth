package federation

import (
	"context"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// Adapter carries one kind of upstream provider: its protocol and its identity
// semantics (FED-002). Social providers are not ordinary OIDC providers: their
// subjects, tenants and email assertions mean different things, so each has
// its own adapter rather than a configuration of the generic one.
//
// The broker is extended by registering adapters at build time
// (RegisterAdapter); the connection API then accepts the adapter's name.
type Adapter struct {
	Name string
	// OIDC adapters validate ID tokens (discovery, nonce, login_hint, JWKS).
	OIDC bool
	// EmailLinkable reports whether the provider's verified-email assertion is
	// strong enough to support trusted_verified_email linking (FED-004).
	EmailLinkable bool
	// Prepare applies provider defaults to a connection and checks it.
	Prepare func(in *Input) error
	// Identity resolves the upstream identity from the access token for
	// adapters that are not OIDC.
	Identity func(ctx context.Context, s *Service, p *Provider, accessToken string) (*Upstream, error)
	// Normalize applies provider semantics to an identity validated from an
	// ID token, for example which email assertions to believe.
	Normalize func(p *Provider, up *Upstream, claims map[string]any)
}

var (
	adaptersMu sync.RWMutex
	adapters   = map[string]*Adapter{}
)

// RegisterAdapter adds an adapter. Names are lowercase and unique; a
// registered adapter cannot be replaced.
func RegisterAdapter(a *Adapter) {
	adaptersMu.Lock()
	defer adaptersMu.Unlock()
	if a == nil || !adapterName.MatchString(a.Name) || a.Prepare == nil || (!a.OIDC && a.Identity == nil) {
		panic("federation: invalid adapter registration")
	}
	if _, dup := adapters[a.Name]; dup {
		panic("federation: adapter " + a.Name + " registered twice")
	}
	adapters[a.Name] = a
}

func adapterFor(name string) (*Adapter, bool) {
	adaptersMu.RLock()
	defer adaptersMu.RUnlock()
	a, ok := adapters[name]
	return a, ok
}

// AdapterNames lists the registered adapters.
func AdapterNames() []string {
	adaptersMu.RLock()
	defer adaptersMu.RUnlock()
	out := make([]string, 0, len(adapters))
	for n := range adapters {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// isOIDC reports whether a connection validates ID tokens.
func isOIDC(p *Provider) bool {
	a, ok := adapterFor(p.Adapter)
	return ok && a.OIDC
}

// Built-in adapters.
const (
	AdapterGoogle    = "google"
	AdapterMicrosoft = "microsoft"
)

func init() {
	RegisterAdapter(&Adapter{Name: AdapterOIDC, OIDC: true, EmailLinkable: true, Prepare: func(in *Input) error {
		if in.Issuer == "" {
			return problem.ErrValidation.WithField("issuer", "required for OIDC connections")
		}
		if in.Config.Scopes == nil {
			in.Config.Scopes = []string{"openid", "email", "profile"}
		}
		return nil
	}})
	RegisterAdapter(&Adapter{Name: AdapterGitHub, EmailLinkable: true, Prepare: func(in *Input) error {
		if in.Issuer == "" {
			in.Issuer = "https://github.com"
		}
		if in.Config.AuthorizationEndpoint == "" {
			in.Config.AuthorizationEndpoint = "https://github.com/login/oauth/authorize"
		}
		if in.Config.TokenEndpoint == "" {
			in.Config.TokenEndpoint = "https://github.com/login/oauth/access_token"
		}
		if in.Config.APIBaseURL == "" {
			in.Config.APIBaseURL = "https://api.github.com"
		}
		if in.Config.Scopes == nil {
			in.Config.Scopes = []string{"read:user", "user:email"} // FED-018: minimal
		}
		return nil
	}, Identity: func(ctx context.Context, s *Service, p *Provider, accessToken string) (*Upstream, error) {
		return s.githubIdentity(ctx, p, accessToken)
	}})
	// Google: one issuer for consumer and Workspace accounts. The subject is
	// stable per Google account; a Workspace domain is the "hd" claim, so
	// allowed_tenants restricts sign-in to listed Workspace domains (consumer
	// accounts carry no hd and are then refused). Google's email_verified is
	// believed only where Google is authoritative for the address (see
	// googleEmailAuthoritative).
	RegisterAdapter(&Adapter{Name: AdapterGoogle, OIDC: true, EmailLinkable: true, Prepare: func(in *Input) error {
		if in.Issuer == "" {
			in.Issuer = "https://accounts.google.com"
		}
		if in.Issuer != "https://accounts.google.com" {
			return problem.ErrValidation.WithField("issuer", "the google adapter uses https://accounts.google.com")
		}
		if len(in.Config.AllowedTenants) > 0 && in.Config.TenantClaim == "" {
			in.Config.TenantClaim = "hd"
		}
		if in.Config.Scopes == nil {
			in.Config.Scopes = []string{"openid", "email", "profile"}
		}
		return nil
	}, Normalize: func(p *Provider, up *Upstream, claims map[string]any) {
		if up.EmailVerified && !googleEmailAuthoritative(up.Email, claims) {
			up.EmailVerified = false
		}
	}})
	// Microsoft Entra ID (work and school accounts): a per-tenant issuer
	// selected by the "tid" claim, so allowed_tenants is mandatory. The
	// subject is pairwise per application, and the email claim is a mutable,
	// unverified attribute: it never counts as verified, so trusted email
	// linking is unavailable.
	RegisterAdapter(&Adapter{Name: AdapterMicrosoft, OIDC: true, Prepare: func(in *Input) error {
		const base = "https://login.microsoftonline.com"
		if in.Issuer == "" {
			in.Issuer = base + "/{tenant}/v2.0"
		}
		if in.Issuer != base+"/{tenant}/v2.0" {
			return problem.ErrValidation.WithField("issuer", "the microsoft adapter uses "+base+"/{tenant}/v2.0")
		}
		in.Config.MultiTenantIssuer, in.Config.TenantClaim = true, "tid"
		if len(in.Config.AllowedTenants) == 0 {
			return problem.ErrValidation.WithField("config.allowed_tenants", "list the Entra tenant IDs allowed to sign in")
		}
		if in.Config.AuthorizationEndpoint == "" {
			in.Config.AuthorizationEndpoint = base + "/organizations/oauth2/v2.0/authorize"
		}
		if in.Config.TokenEndpoint == "" {
			in.Config.TokenEndpoint = base + "/organizations/oauth2/v2.0/token"
		}
		if in.Config.JWKSURI == "" {
			in.Config.JWKSURI = base + "/common/discovery/v2.0/keys"
		}
		if in.Config.Scopes == nil {
			in.Config.Scopes = []string{"openid", "email", "profile"}
		}
		return nil
	}, Normalize: func(p *Provider, up *Upstream, claims map[string]any) {
		up.EmailVerified = false
	}})
}

// normalize applies the connection's adapter semantics to a validated
// identity. An adapter whose email assertions are not trusted never yields a
// verified email.
func normalize(p *Provider, up *Upstream, claims map[string]any) {
	a, ok := adapterFor(p.Adapter)
	if !ok {
		return
	}
	if a.Normalize != nil {
		a.Normalize(p, up, claims)
	}
	if !a.EmailLinkable {
		up.EmailVerified = false
	}
}

// googleConsumerDomains are the domains of consumer Google accounts, whose
// addresses Google issues itself.
var googleConsumerDomains = []string{"gmail.com", "googlemail.com"}

// googleEmailAuthoritative reports whether Google is authoritative for email
// (FED-002, FED-004): a consumer Gmail address, or a Workspace account whose
// "hd" claim names the address's own domain. Any other Google account may
// carry email_verified=true for an address in a domain Google does not run
// (a consumer account registered with a corporate address, or a former
// employee's), and that assertion must not verify or link a local address.
// The hd claim is read from the ID token itself: the connection's tenant is
// filled in only when allowed_tenants is configured.
func googleEmailAuthoritative(email string, claims map[string]any) bool {
	c, _, err := canonical.Email(email)
	if err != nil {
		return false
	}
	domain := canonical.EmailDomain(c)
	if slices.Contains(googleConsumerDomains, domain) {
		return true
	}
	hd, _ := claims["hd"].(string)
	if hd == "" {
		return false
	}
	d, err := canonical.Domain(hd)
	return err == nil && strings.EqualFold(d, domain)
}

var adapterName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
