package oauth

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authentication"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/token"
)

// DeviceAuthorization is the RFC 8628 §3.2 response.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func normalizeUserCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

// DeviceAuthorize starts a device flow for an authenticated (or public device) client.
func (s *Service) DeviceAuthorize(ctx context.Context, rlm *realm.Realm, auth application.ClientAuthInput, endpoint string, f url.Values) (*DeviceAuthorization, *Error) {
	c, err := s.Apps.Authenticate(ctx, rlm.ID, rlm.Issuer, endpoint, auth)
	if err != nil {
		return nil, ErrInvalidClient
	}
	if !grantAllowed(rlm, c, application.GrantDeviceCode) {
		return nil, ErrUnauthorizedClient("device flow not allowed")
	}
	scopes, resources, oe := s.ResolveScopes(ctx, rlm, c, f.Get("scope"), f["resource"], "user")
	if oe != nil {
		return nil, oe
	}
	orgID := ""
	if o := f.Get("organization"); o != "" {
		if org, err := s.Orgs.Resolve(ctx, rlm.ID, o); err == nil {
			orgID = org.ID
		}
	}
	// The user approves on another device through the application-provided login
	// UI; without one the flow cannot be completed, so it is refused up front
	// rather than advertising an unusable verification URI.
	ui := c.LoginUIURL
	if ui == "" {
		ui = rlm.Policy.Interaction.LoginUIURL
	}
	if ui == "" {
		return nil, ErrInvalidRequest("the device flow requires a configured login UI (realm interaction.login_ui_url or the client's login_ui_url)")
	}
	deviceCode := secret.Token(secret.PrefixDeviceCode)
	userCode := secret.UserCode()
	ttl := s.d.Cfg.Tokens.DeviceCodeTTL
	now := s.d.Now()
	_, err = s.d.DB.Pool.Exec(ctx, `INSERT INTO device_codes (id, realm_id, client_ref, device_code_digest, user_code_digest, scopes, resource_ids,
		requested_org_id, interval_seconds, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,5,$9,$10)`, ids.New(ids.DeviceCode), rlm.ID, c.Ref,
		secret.Digest(deviceCode), secret.Digest(normalizeUserCode(userCode)), scopes, resources, nilIfEmpty(orgID), now.Add(ttl), now)
	if err != nil {
		return nil, serverError(s, err)
	}
	return &DeviceAuthorization{DeviceCode: deviceCode, UserCode: userCode, VerificationURI: ui,
		VerificationURIComplete: authentication.BuildRedirect(ui, map[string]string{"user_code": userCode}), ExpiresIn: int(ttl.Seconds()), Interval: 5}, nil
}

// StartDeviceTransaction begins the user-side approval for a user code. The user
// must explicitly confirm the requesting client (consent is always shown) so a
// phished code cannot be approved blindly (§18.1 device stance, TEST-068).
func (s *Service) StartDeviceTransaction(ctx context.Context, rlm *realm.Realm, userCode, clientIP, ua string) (*authentication.Started, map[string]any, error) {
	norm := normalizeUserCode(userCode)
	if len(norm) != 8 {
		return nil, nil, problem.ErrInvalidProof
	}
	var id, clientRef string
	var scopes, resources []string
	var org *string
	var expires time.Time
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT id, client_ref, scopes, resource_ids, requested_org_id, expires_at FROM device_codes
		WHERE realm_id=$1 AND user_code_digest=$2 AND state='pending'`, rlm.ID, secret.Digest(norm)).Scan(&id, &clientRef, &scopes, &resources, &org, &expires)
	if err != nil || !s.d.Now().Before(expires) {
		return nil, nil, problem.ErrInvalidProof
	}
	c, err := s.Apps.ClientByRef(ctx, nil, rlm.ID, clientRef)
	if err != nil || !c.Active() {
		return nil, nil, problem.ErrInvalidProof
	}
	o := ""
	if org != nil {
		o = *org
	}
	st, err := s.Auth.Start(ctx, authentication.StartInput{RealmID: rlm.ID, Client: c, Mode: "headless", Intent: "device", Scopes: scopes,
		ResourceIDs: resources, Prompt: []string{"consent"}, OrgID: o, DeviceCodeID: id, ClientIP: clientIP, UserAgent: ua})
	if err != nil {
		return nil, nil, err
	}
	return st, map[string]any{"client_name": c.Name, "client_id": c.ClientID, "scopes": scopes, "expires_at": expires}, nil
}

func (s *Service) deviceGrant(ctx context.Context, rlm *realm.Realm, c *application.Client, f url.Values, cnf *token.Confirmation) (*IssuedTokens, *Error) {
	dc := f.Get("device_code")
	if !secret.HasPrefix(dc, secret.PrefixDeviceCode) {
		return nil, ErrInvalidGrant("invalid device_code")
	}
	var out *IssuedTokens
	var oe *Error
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		out, oe = nil, nil // a retried transaction starts clean (DB-014)
		var id, clientRef, state string
		var grantID *string
		var last *time.Time
		var interval int
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT id, client_ref, state, grant_id, last_polled_at, interval_seconds, expires_at FROM device_codes
			WHERE realm_id=$1 AND device_code_digest=$2 FOR UPDATE`, rlm.ID, secret.Digest(dc)).Scan(&id, &clientRef, &state, &grantID, &last, &interval, &expires)
		if err != nil {
			if storage.IsNoRows(err) {
				oe = ErrInvalidGrant("invalid device_code")
				return nil
			}
			return err
		}
		if clientRef != c.Ref {
			oe = ErrInvalidGrant("device_code was issued to another client")
			return nil
		}
		now := s.d.Now()
		if !now.Before(expires) {
			_, _ = tx.Exec(ctx, `UPDATE device_codes SET state='expired' WHERE id=$1`, id)
			oe = ErrExpiredToken
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE device_codes SET last_polled_at=$2 WHERE id=$1`, id, now); err != nil {
			return err
		}
		switch state {
		case "pending":
			if last != nil && now.Sub(*last) < time.Duration(interval)*time.Second {
				_, _ = tx.Exec(ctx, `UPDATE device_codes SET interval_seconds=interval_seconds+5 WHERE id=$1`, id)
				oe = ErrSlowDown
				return nil
			}
			oe = ErrAuthorizationPending
			return nil
		case "denied":
			oe = ErrAccessDenied
			return nil
		case "consumed", "expired":
			oe = ErrInvalidGrant("device_code already used")
			return nil
		}
		tag, err := tx.Exec(ctx, `UPDATE device_codes SET state='consumed' WHERE id=$1 AND state='approved'`, id)
		if err != nil || tag.RowsAffected() != 1 {
			oe = ErrInvalidGrant("device_code already used")
			return err
		}
		g, err := s.Sessions.GrantTx(ctx, tx, *grantID)
		if err != nil {
			return err
		}
		var e *Error
		out, e, err = s.issueForUserGrant(ctx, tx, rlm, c, g, g.Scopes, f["resource"], "", true, cnf)
		if err != nil {
			return err
		}
		if e != nil {
			oe = e
			return nil
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "token.issued", RealmID: rlm.ID, OrgID: g.OrgID, Actor: audit.Ref{Type: "client", ID: c.Ref},
			Subject: &audit.Ref{Type: "user", ID: g.SubjectID}, ClientID: c.ClientID, GrantID: g.ID, Category: "token",
			Metadata: map[string]any{"grant_type": "device_code"}})
		return err
	})
	if err != nil {
		return nil, serverError(s, err)
	}
	return out, oe
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
