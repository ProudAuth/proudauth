// Package provision creates realms with their built-in configuration and performs
// the operator-only bootstrap of the first administrator (DEP-007, SEC-011).
package provision

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/token"
)

// Built-in scope names.
const (
	ScopeAccount = "proudauth:account"
	ScopeAdmin   = "proudauth:admin"
	CLIClientID  = application.OperatorClientID
)

// OIDCScopes are the protocol scopes every realm declares.
var OIDCScopes = []application.ScopeInput{
	{Name: "openid", Description: "Sign you in", ConsentText: "Verify your identity", Sensitivity: "low", IsDefault: true},
	{Name: "profile", Description: "Basic profile", ConsentText: "See your name and profile", Sensitivity: "normal"},
	{Name: "email", Description: "Email address", ConsentText: "See your email address", Sensitivity: "normal"},
	{Name: "phone", Description: "Phone number", ConsentText: "See your phone number", Sensitivity: "normal"},
	{Name: "address", Description: "Postal address", ConsentText: "See your address", Sensitivity: "high"},
	{Name: "offline_access", Description: "Offline access", ConsentText: "Stay signed in when you are away", Sensitivity: "high"},
}

// Provisioner creates realms.
type Provisioner struct {
	d      *runtime.Deps
	Realms *realm.Service
	Apps   *application.Service
	Authz  *authorization.Service
	Keys   *token.KeyManager
	Users  *identity.Service
	Auth   *authentication.Service
}

// New returns a provisioner.
func New(d *runtime.Deps, r *realm.Service, a *application.Service, az *authorization.Service, k *token.KeyManager, u *identity.Service, auth *authentication.Service) *Provisioner {
	return &Provisioner{d: d, Realms: r, Apps: a, Authz: az, Keys: k, Users: u, Auth: auth}
}

// CreateRealm creates a realm with built-in permissions, roles, system resources,
// OIDC scopes, the first-party CLI client and an active signing key, atomically.
func (p *Provisioner) CreateRealm(ctx context.Context, name, displayName string, policy realm.Policy, actor audit.Ref) (*realm.Realm, error) {
	var out *realm.Realm
	err := p.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		r, err := p.Realms.CreateTx(ctx, tx, name, displayName, policy)
		if err != nil {
			return err
		}
		if err := p.Authz.SeedBuiltInsTx(ctx, tx, r.ID); err != nil {
			return err
		}
		no := false
		account, err := p.Apps.CreateResourceTx(ctx, tx, r.ID, application.ResourceInput{Name: "Account self-service API", Audience: r.Issuer + "/account",
			TokenFormat: "jwt", VerificationMode: application.ModeStrictOnline, RequiresOrganization: &no, Kind: application.KindAccount,
			Scopes: []application.ScopeInput{{Name: ScopeAccount, Description: "Manage your account", ConsentText: "Manage your account and security settings", Sensitivity: "high"}}}, actor)
		if err != nil {
			return err
		}
		admin, err := p.Apps.CreateResourceTx(ctx, tx, r.ID, application.ResourceInput{Name: "Administration API", Audience: r.Issuer + "/admin",
			TokenFormat: "jwt", VerificationMode: application.ModeStrictOnline, RequiresOrganization: &no, Kind: application.KindAdmin,
			Scopes: []application.ScopeInput{{Name: ScopeAdmin, Description: "Administer the identity domain", ConsentText: "Administer identities and configuration", Sensitivity: "privileged"}}}, actor)
		if err != nil {
			return err
		}
		userinfo, err := p.Apps.CreateResourceTx(ctx, tx, r.ID, application.ResourceInput{Name: "OIDC UserInfo", Audience: r.Issuer + "/userinfo",
			TokenFormat: "jwt", VerificationMode: application.ModeStrictOnline, RequiresOrganization: &no, Kind: application.KindUserInfo}, actor)
		if err != nil {
			return err
		}
		for _, sc := range OIDCScopes {
			res := userinfo.ID
			if sc.Name == "offline_access" {
				res = ""
			}
			if err := p.Apps.CreateOIDCScopeTx(ctx, tx, r.ID, res, sc); err != nil {
				return err
			}
		}
		cli, _, err := p.Apps.CreateClientTx(ctx, tx, r.ID, application.ClientInput{ClientID: CLIClientID, Name: "ProudAuth CLI",
			Description: "First-party administrative command-line client", Type: application.TypeNative,
			GrantTypes: []string{application.GrantAuthorizationCode, application.GrantRefreshToken, application.GrantDeviceCode},
			FirstParty: true, ConsentMode: "preauthorized", SecurityProfile: "privileged", RedirectURIs: []string{"http://127.0.0.1/callback"},
			Environment: "production"}, actor)
		if err != nil {
			return err
		}
		for _, g := range []struct {
			res    string
			scopes []string
		}{{account.ID, []string{ScopeAccount}}, {admin.ID, []string{ScopeAdmin}}, {userinfo.ID, []string{"openid", "profile", "email", "phone"}}} {
			if err := p.Apps.SetResourceGrantTx(ctx, tx, r.ID, cli.Ref, g.res, g.scopes, []string{"user"}, application.ExchangePolicy{}, actor); err != nil {
				return err
			}
		}
		if err := p.Keys.EnsureActive(ctx, tx, r.ID, p.d.Cfg.Keys.SigningAlgorithm); err != nil {
			return err
		}
		if _, err := p.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.created", RealmID: r.ID, Actor: actor,
			Target: &audit.Ref{Type: "realm", ID: r.ID}, Metadata: map[string]any{"name": name, "issuer": r.Issuer}}); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ErrAlreadyBootstrapped refuses repeated bootstrap (SEC-011).
var ErrAlreadyBootstrapped = errors.New("realm already has an initial administrator; use the break-glass procedure instead")

// BootstrapResult is shown once on the operator console.
type BootstrapResult struct {
	RealmID    string
	UserID     string
	SetupToken string
	ExpiresAt  time.Time
}

// BootstrapAdmin creates the initial realm administrator through the local operator
// channel. There is no default password: the operator receives a one-time,
// expiring setup token, and the account is required to enroll MFA at first sign-in
// (MFA-003, DEP-007). Repeated bootstrap is refused unless breakGlass is set, which
// is audited as an emergency action.
func (p *Provisioner) BootstrapAdmin(ctx context.Context, realmName, email, username string, ttl time.Duration, breakGlass bool, operator string) (*BootstrapResult, error) {
	r, err := p.Realms.ByName(ctx, realmName)
	if err != nil {
		return nil, err
	}
	if r.BootstrappedAt != nil && !breakGlass {
		return nil, ErrAlreadyBootstrapped
	}
	if ttl == 0 {
		ttl = time.Hour
	}
	if ttl < time.Minute || ttl > 24*time.Hour {
		return nil, fmt.Errorf("setup token lifetime %s outside 1m..24h", ttl)
	}
	actor := audit.Ref{Type: "operator", ID: "local:" + operator}
	var res BootstrapResult
	err = p.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var bootstrapped *time.Time
		if err := tx.QueryRow(ctx, `SELECT bootstrapped_at FROM realms WHERE id=$1 FOR UPDATE`, r.ID).Scan(&bootstrapped); err != nil {
			return err
		}
		if bootstrapped != nil && !breakGlass {
			return ErrAlreadyBootstrapped
		}
		u, err := p.Users.CreateTx(ctx, tx, r.ID, identity.CreateInput{Email: email, Username: username, DisplayName: "Administrator",
			State: identity.StateActive, CreatedVia: "bootstrap", Protected: true,
			RequiredActions: []string{identity.ActionConfigureTOTP, identity.ActionVerifyEmail}})
		if err != nil {
			return err
		}
		role, err := p.Authz.RoleByName(ctx, tx, r.ID, "realm", authorization.RoleRealmAdmin)
		if err != nil {
			return err
		}
		if _, err := p.Authz.AssignTx(ctx, tx, r.ID, nil, authorization.AssignInput{RoleID: role.ID,
			Subject: authorization.Subject{Type: authorization.SubjectUser, ID: u.ID}, Scope: authorization.Scope{Type: authorization.ScopeRealm, ID: r.ID},
			Source: "bootstrap", Reason: "initial administrator", SkipCeiling: true}, actor); err != nil {
			return err
		}
		st, err := p.Auth.IssueAccountSetupTx(ctx, tx, r.ID, u.ID, ttl, false, r.DisplayName)
		if err != nil {
			return err
		}
		if err := p.Realms.MarkBootstrapped(ctx, tx, r.ID); err != nil {
			return err
		}
		evType := "bootstrap.admin_created"
		if breakGlass {
			evType = "bootstrap.break_glass_admin_created"
		}
		if _, err := p.d.Audit.Record(ctx, tx, audit.Event{Type: evType, RealmID: r.ID, Actor: actor, Subject: &audit.Ref{Type: "user", ID: u.ID},
			Category: "emergency", Metadata: map[string]any{"expires_at": st.ExpiresAt}}); err != nil {
			return err
		}
		res = BootstrapResult{RealmID: r.ID, UserID: u.ID, SetupToken: st.Token, ExpiresAt: st.ExpiresAt}
		return nil
	})
	p.Realms.Invalidate(realmName)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
