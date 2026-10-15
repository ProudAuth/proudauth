package application

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// Client protocols.
const (
	ProtocolOIDC = "oidc"
	ProtocolSAML = "saml"
)

// SAMLClientInput describes the client that backs a SAML application
// (APP-018). The SAML profile reuses the authentication transaction, consent,
// organization policy, session and audit machinery, all of which are keyed
// by a client; the backing client is how a SAML application takes part.
//
// The client is confidential, uses private_key_jwt with no registered key and
// only the authorization_code grant, and its single redirect URI is the
// identity provider's own SAML continuation endpoint. Codes issued to it are
// redeemed internally by the SAML profile (never at the token endpoint), and
// OAuth client authentication refuses SAML clients outright.
type SAMLClientInput struct {
	Name                 string
	Description          string
	ProjectID            string
	Environment          string
	FirstParty           bool
	ConsentMode          string
	ConsentTermsVersion  string
	LoginUIURL           string
	RequireMFA           bool
	MaxSessionAgeSeconds int
	AllowRememberMe      bool
	// ContinueURI is the realm's SAML continuation endpoint.
	ContinueURI string
}

func (in *SAMLClientInput) normalize() *problem.Error {
	verr := problem.ErrValidation
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 {
		return verr.WithField("name", "required, at most 200 characters")
	}
	if len(in.Description) > 1000 {
		return verr.WithField("description", "at most 1000 characters")
	}
	if in.Environment == "" {
		in.Environment = "production"
	}
	if in.Environment != "production" && in.Environment != "staging" && in.Environment != "development" {
		return verr.WithField("environment", "production, staging or development")
	}
	if len(in.ConsentTermsVersion) > 64 {
		return verr.WithField("consent_terms_version", "at most 64 characters")
	}
	if in.ConsentMode == "" {
		if in.FirstParty {
			in.ConsentMode = "preauthorized"
		} else {
			in.ConsentMode = "required"
		}
	}
	if in.ConsentMode != "required" && in.ConsentMode != "preauthorized" {
		return verr.WithField("consent_mode", "required or preauthorized")
	}
	if in.LoginUIURL != "" {
		if msg := ValidateRedirectRegistration(in.LoginUIURL, TypeConfidential, in.Environment); msg != "" {
			return verr.WithField("login_ui_url", msg)
		}
	}
	if in.MaxSessionAgeSeconds < 0 || in.MaxSessionAgeSeconds > 90*24*3600 {
		return verr.WithField("max_session_age_seconds", "must be within 0..7776000")
	}
	if in.ContinueURI == "" {
		return problem.ErrInternal
	}
	return nil
}

func (in *SAMLClientInput) tokenPolicy() []byte {
	tp, _ := json.Marshal(TokenPolicy{RequireMFA: in.RequireMFA, MaxSessionAgeSeconds: in.MaxSessionAgeSeconds})
	return tp
}

// CreateSAMLClientTx registers the backing client of a new SAML application.
func (s *Service) CreateSAMLClientTx(ctx context.Context, tx pgx.Tx, realmID string, in SAMLClientInput, actor audit.Ref) (*Client, error) {
	if in.Environment == "" && in.ProjectID != "" {
		_ = tx.QueryRow(ctx, `SELECT environment FROM projects WHERE realm_id=$1 AND id=$2`, realmID, in.ProjectID).Scan(&in.Environment)
	}
	if perr := in.normalize(); perr != nil {
		return nil, perr
	}
	if err := s.checkProjectEnvironment(ctx, tx, realmID, in.ProjectID, in.Environment); err != nil {
		return nil, err
	}
	ref := ids.New(ids.Client)
	clientID := ids.New("saml")
	now := s.d.Now()
	security := "standard"
	if !in.FirstParty && in.ConsentMode == "required" {
		security = "third_party"
	}
	_, err := tx.Exec(ctx, `INSERT INTO clients (id, realm_id, client_id, project_id, name, description, client_type, token_endpoint_auth_method,
		grant_types, security_profile, first_party, consent_mode, allow_remember_me, environment, login_ui_url, token_policy, created_at,
		updated_at, consent_terms_version, protocol)
		VALUES ($1,$2,$3,$4,$5,$6,'confidential','private_key_jwt',$7,$8,$9,$10,$11,$12,$13,$14,$15,$15,$16,'saml')`,
		ref, realmID, clientID, nilIfEmpty(in.ProjectID), in.Name, nilIfEmpty(in.Description), []string{GrantAuthorizationCode}, security,
		in.FirstParty, in.ConsentMode, in.AllowRememberMe, in.Environment, nilIfEmpty(in.LoginUIURL), in.tokenPolicy(), now,
		nilIfEmpty(in.ConsentTermsVersion))
	if err != nil {
		if storage.IsForeignKeyViolation(err) {
			return nil, problem.ErrValidation.WithField("project_id", "unknown project")
		}
		return nil, err
	}
	if err := s.replaceURIs(ctx, tx, realmID, ref, []string{in.ContinueURI}, nil, nil); err != nil {
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.created", RealmID: realmID, Actor: actor, Category: "application",
		Target: &audit.Ref{Type: "client", ID: ref}, Metadata: map[string]any{"client_id": clientID, "protocol": ProtocolSAML,
			"first_party": in.FirstParty, "consent_mode": in.ConsentMode}}); err != nil {
		return nil, err
	}
	return s.ClientByRef(ctx, tx, realmID, ref)
}

// UpdateSAMLClientTx updates the backing client of a SAML application. Its
// type, credentials, grant and redirect never change.
func (s *Service) UpdateSAMLClientTx(ctx context.Context, tx pgx.Tx, realmID, ref string, in SAMLClientInput, actor audit.Ref) (*Client, error) {
	cur, err := scanClient(tx.QueryRow(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, ref))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if cur.Protocol != ProtocolSAML {
		return nil, problem.ErrConflict
	}
	if in.Environment == "" {
		in.Environment = cur.Environment
	}
	if in.Environment != cur.Environment {
		return nil, problem.ErrValidation.WithField("environment", "an application's environment cannot change; register a new one")
	}
	if perr := in.normalize(); perr != nil {
		return nil, perr
	}
	if err := s.checkProjectEnvironment(ctx, tx, realmID, in.ProjectID, in.Environment); err != nil {
		return nil, err
	}
	security := "standard"
	if !in.FirstParty && in.ConsentMode == "required" {
		security = "third_party"
	}
	if _, err := tx.Exec(ctx, `UPDATE clients SET name=$3, description=$4, project_id=$5, first_party=$6, consent_mode=$7, consent_terms_version=$8,
		login_ui_url=$9, token_policy=$10, allow_remember_me=$11, security_profile=$12, version=version+1, updated_at=$13 WHERE realm_id=$1 AND id=$2`,
		realmID, ref, in.Name, nilIfEmpty(in.Description), nilIfEmpty(in.ProjectID), in.FirstParty, in.ConsentMode, nilIfEmpty(in.ConsentTermsVersion),
		nilIfEmpty(in.LoginUIURL), in.tokenPolicy(), in.AllowRememberMe, security, s.d.Now()); err != nil {
		if storage.IsForeignKeyViolation(err) {
			return nil, problem.ErrValidation.WithField("project_id", "unknown project")
		}
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.updated", RealmID: realmID, Actor: actor, Category: "application",
		Target: &audit.Ref{Type: "client", ID: ref}, Metadata: map[string]any{"client_id": cur.ClientID, "version": cur.Version + 1,
			"protocol": ProtocolSAML}}); err != nil {
		return nil, err
	}
	return s.ClientByRef(ctx, tx, realmID, ref)
}
