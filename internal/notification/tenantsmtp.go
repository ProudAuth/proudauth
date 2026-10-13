package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// TenantSMTP is an organization's own mail server (TEN-022). The password is
// stored encrypted and bound to the realm and organization, so it can only be
// decrypted to send that organization's mail; it is never returned.
type TenantSMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	TLSMode  string `json:"tls_mode"`
	// HasPassword is set on reads only.
	HasPassword bool `json:"has_password,omitempty"`
}

func smtpAAD(realmID, orgID string) []byte { return []byte("smtp:" + realmID + ":" + orgID) }

// SetTenantSMTP stores an organization's mail server. A nil password keeps the
// stored one.
func (s *Service) SetTenantSMTP(ctx context.Context, realmID, orgID string, in TenantSMTP, password *string, actor audit.Ref) error {
	if orgID == "" {
		return problem.ErrValidation.WithField("organization_id", "tenant mail servers belong to an organization")
	}
	host, err := canonical.Domain(in.Host)
	if err != nil {
		return problem.ErrValidation.WithField("host", "a DNS host name")
	}
	in.Host = host
	// Refused at save as well as at dial time (PRV-003), so a setting that
	// could never deliver is not accepted.
	if !egress.HostAllowed(host) {
		return problem.ErrValidation.WithField("host", "outside the deployment's destination residency policy")
	}
	if in.Port != 25 && in.Port != 465 && in.Port != 587 && in.Port != 2525 {
		return problem.ErrValidation.WithField("port", "25, 465, 587 or 2525")
	}
	// Plain-text SMTP would expose the tenant's credentials and mail.
	if in.TLSMode != "starttls" && in.TLSMode != "implicit" {
		return problem.ErrValidation.WithField("tls_mode", "starttls or implicit")
	}
	if len(in.Username) > 256 {
		return problem.ErrValidation.WithField("username", "too long")
	}
	in.HasPassword = false
	cfg, _ := json.Marshal(in)
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var ct []byte
		var ver int
		if password != nil {
			if len(*password) > 1024 {
				return problem.ErrValidation.WithField("password", "too long")
			}
			if ct, ver, err = s.d.Keys.Encrypt(keys.PurposeData, []byte(*password), smtpAAD(realmID, orgID)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_settings (realm_id, organization_id, smtp_config, smtp_secret_ciphertext, key_version)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT (realm_id, organization_id) DO UPDATE SET smtp_config=EXCLUDED.smtp_config,
			smtp_secret_ciphertext=CASE WHEN $6 THEN EXCLUDED.smtp_secret_ciphertext ELSE notification_settings.smtp_secret_ciphertext END,
			key_version=CASE WHEN $6 THEN EXCLUDED.key_version ELSE notification_settings.key_version END,
			version=notification_settings.version+1, updated_at=now()`, realmID, orgID, cfg, ct, nilIfZero(ver), password != nil); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "notification.smtp.updated", RealmID: realmID, OrgID: orgID, Actor: actor, Category: "configuration",
			Metadata: map[string]any{"host": in.Host, "port": in.Port, "tls_mode": in.TLSMode, "password_changed": password != nil}})
		return err
	})
}

// ClearTenantSMTP removes an organization's mail server; its mail goes
// through the deployment's sender again.
func (s *Service) ClearTenantSMTP(ctx context.Context, realmID, orgID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_settings SET smtp_config='{}', smtp_secret_ciphertext=NULL, key_version=NULL,
			version=version+1, updated_at=now() WHERE realm_id=$1 AND organization_id=$2`, realmID, orgID); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "notification.smtp.cleared", RealmID: realmID, OrgID: orgID, Actor: actor, Category: "configuration"})
		return err
	})
}

// GetTenantSMTP returns an organization's mail server without its secret.
func (s *Service) GetTenantSMTP(ctx context.Context, realmID, orgID string) (*TenantSMTP, error) {
	var raw []byte
	var ct []byte
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT smtp_config, smtp_secret_ciphertext FROM notification_settings WHERE realm_id=$1 AND organization_id=$2`,
		realmID, orgID).Scan(&raw, &ct)
	if err != nil {
		return nil, problem.ErrNotFound
	}
	var t TenantSMTP
	if json.Unmarshal(raw, &t) != nil || t.Host == "" {
		return nil, problem.ErrNotFound
	}
	t.HasPassword = len(ct) > 0
	return &t, nil
}

// tenantSender builds the sender for an organization's own mail server, or
// nil when it has none. Connections go only to addresses the delivery egress
// policy allows, checked at dial time.
func (s *Service) tenantSender(ctx context.Context, realmID, orgID string) (*SMTPSender, error) {
	if orgID == "" {
		return nil, nil
	}
	var raw, ct []byte
	var ver *int
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT smtp_config, smtp_secret_ciphertext, key_version FROM notification_settings
		WHERE realm_id=$1 AND organization_id=$2`, realmID, orgID).Scan(&raw, &ct, &ver); err != nil {
		return nil, nil
	}
	var t TenantSMTP
	if json.Unmarshal(raw, &t) != nil || t.Host == "" {
		return nil, nil
	}
	password := ""
	if len(ct) > 0 {
		pt, err := s.d.Keys.Decrypt(keys.PurposeData, ct, smtpAAD(realmID, orgID))
		if err != nil {
			return nil, fmt.Errorf("tenant SMTP credential unavailable: %w", err)
		}
		password = string(pt)
	}
	policy := egress.Policy{AllowPrivate: s.d.Cfg.Delivery.AllowPrivateWebhooks, AllowCIDRs: s.d.Cfg.Delivery.EgressAllowlist}
	return &SMTPSender{Host: t.Host, Port: t.Port, Username: t.Username, PasswordRef: password, TLSMode: t.TLSMode,
		Dial: func(ctx context.Context, host, port string) (net.Conn, error) {
			if !egress.HostAllowed(host) {
				return nil, egress.ErrResidency
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !policy.Allowed(ip) {
					return nil, egress.ErrForbiddenDestination
				}
			}
			if len(ips) == 0 {
				return nil, egress.ErrForbiddenDestination
			}
			// Every resolved address was checked above; try them in order so one
			// unreachable address does not stop delivery.
			d := &net.Dialer{Timeout: 10 * time.Second}
			var lastErr error
			for _, ip := range ips {
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
				if ctx.Err() != nil {
					break
				}
			}
			return nil, lastErr
		}}, nil
}

func nilIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
