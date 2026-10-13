package notification

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// SettingsPatch updates delivery settings for a realm or organization; nil
// fields keep their current values.
type SettingsPatch struct {
	OrganizationID string
	SenderAddress  *string
	SenderName     *string
	ReplyTo        *string
	DefaultLocale  *string
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// UpdateSettings upserts notification settings with an audit record. The
// notification module owns its tables (ARC-001); callers validate input.
func (s *Service) UpdateSettings(ctx context.Context, realmID string, in SettingsPatch, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_settings (realm_id, organization_id, sender_address, sender_name, reply_to, default_locale)
			VALUES ($1,$2,nullif($3,''),nullif($4,''),nullif($5,''),coalesce(nullif($6,''),'en')) ON CONFLICT (realm_id, organization_id) DO UPDATE SET
			sender_address=CASE WHEN $7 THEN EXCLUDED.sender_address ELSE notification_settings.sender_address END,
			sender_name=CASE WHEN $8 THEN EXCLUDED.sender_name ELSE notification_settings.sender_name END,
			reply_to=CASE WHEN $9 THEN EXCLUDED.reply_to ELSE notification_settings.reply_to END,
			default_locale=CASE WHEN $10 THEN EXCLUDED.default_locale ELSE notification_settings.default_locale END,
			version=notification_settings.version+1, updated_at=now()`, realmID, in.OrganizationID, deref(in.SenderAddress), deref(in.SenderName),
			deref(in.ReplyTo), deref(in.DefaultLocale), in.SenderAddress != nil, in.SenderName != nil, in.ReplyTo != nil, in.DefaultLocale != nil); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "notification.settings.updated", RealmID: realmID, OrgID: in.OrganizationID, Actor: actor})
		return err
	})
}

// TemplateInput replaces a template for one event type and locale.
type TemplateInput struct {
	OrganizationID string
	EventType      string
	Locale         string
	Subject        string
	BodyText       string
	BodyHTML       string
}

// ReplaceTemplate validates and activates a template, disabling the previous
// active version for the same event and locale.
func (s *Service) ReplaceTemplate(ctx context.Context, realmID string, in TemplateInput, actor audit.Ref) (string, error) {
	vars, ok := Variables[in.EventType]
	if !ok {
		return "", problem.ErrValidation.WithField("event_type", "unknown template")
	}
	if err := ValidateTemplate(in.Subject, in.BodyText, in.BodyHTML, vars); err != nil {
		return "", err
	}
	if in.Locale == "" {
		in.Locale = "en"
	}
	id := ids.New(ids.Template)
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_templates SET state='disabled' WHERE realm_id=$1 AND coalesce(organization_id,'')=$2
			AND event_type=$3 AND locale=$4 AND state='active'`, realmID, in.OrganizationID, in.EventType, in.Locale); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_templates (id, realm_id, organization_id, event_type, locale, subject, body_text, body_html)
			VALUES ($1,$2,nullif($3,''),$4,$5,$6,$7,nullif($8,''))`, id, realmID, in.OrganizationID, in.EventType, in.Locale, in.Subject, in.BodyText, in.BodyHTML); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "notification.template.updated", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "template", ID: id}, Metadata: map[string]any{"event_type": in.EventType, "locale": in.Locale}})
		return err
	})
	return id, err
}

// DisableTemplate disables a template, reverting to the built-in catalog.
func (s *Service) DisableTemplate(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE notification_templates SET state='disabled' WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "notification.template.disabled", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "template", ID: id}})
		return err
	})
}
