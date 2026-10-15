package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/hooks"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/webhooks"
	"github.com/proudauth/proudauth/internal/workflow"
)

// Service manages plugin lifecycles.
type Service struct {
	d         *runtime.Deps
	Hooks     *hooks.Service
	Webhooks  *webhooks.Service
	Workflows *workflow.Service
	Authz     *authorization.Service
	Realms    *realm.Service
}

// New builds the service.
func New(d *runtime.Deps, h *hooks.Service, wh *webhooks.Service, wf *workflow.Service, authz *authorization.Service, realms *realm.Service) *Service {
	return &Service{d: d, Hooks: h, Webhooks: wh, Workflows: wf, Authz: authz, Realms: realms}
}

// Plugin is an installed (or uploaded) plugin of a realm.
type Plugin struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Publisher        string     `json:"publisher"`
	State            string     `json:"state"`
	InstalledVersion string     `json:"installed_version,omitempty"`
	PreviousVersion  string     `json:"previous_version,omitempty"`
	InstalledByID    string     `json:"installed_by_id,omitempty"`
	InstalledAt      *time.Time `json:"installed_at,omitempty"`
	Version          int64      `json:"version"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Parts            *Parts     `json:"parts,omitempty"`
}

// Parts lists what an installed plugin manages.
type Parts struct {
	Hooks     []PartRef `json:"hooks"`
	Webhooks  []PartRef `json:"webhooks"`
	Workflows []PartRef `json:"workflows"`
}

// PartRef names one part.
type PartRef struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

// Version is an uploaded plugin version.
type Version struct {
	ID              string          `json:"id"`
	PluginID        string          `json:"plugin_id"`
	Version         string          `json:"version"`
	ManifestVersion int             `json:"manifest_version"`
	Manifest        json.RawMessage `json:"manifest"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	PackageDigest   string          `json:"package_digest"`
	SigningKeyID    string          `json:"signing_key_id"`
	Permissions     []string        `json:"permissions"`
	Status          string          `json:"status"`
	UploadedByID    string          `json:"uploaded_by_id"`
	ReviewedByID    string          `json:"reviewed_by_id,omitempty"`
	ReviewedAt      *time.Time      `json:"reviewed_at,omitempty"`
	ReviewNote      string          `json:"review_note,omitempty"`
	InstalledAt     *time.Time      `json:"installed_at,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	manifestRaw     []byte
	payloadRaw      []byte
	signature       string
}

const pluginCols = `id, name, publisher, state, coalesce(installed_version,''), coalesce(previous_version,''), coalesce(installed_by_id,''), installed_at,
	version, created_at, updated_at`

func scanPlugin(row pgx.Row) (*Plugin, error) {
	var p Plugin
	err := row.Scan(&p.ID, &p.Name, &p.Publisher, &p.State, &p.InstalledVersion, &p.PreviousVersion, &p.InstalledByID, &p.InstalledAt, &p.Version,
		&p.CreatedAt, &p.UpdatedAt)
	return &p, err
}

const versionCols = `id, plugin_id, version, manifest_version, manifest, package_digest, signing_key_id, permissions, status, uploaded_by_id,
	coalesce(reviewed_by_id,''), reviewed_at, coalesce(review_note,''), installed_at, created_at, manifest_raw, payload_raw, signature`

func scanVersion(row pgx.Row) (*Version, error) {
	var v Version
	var manifest []byte
	err := row.Scan(&v.ID, &v.PluginID, &v.Version, &v.ManifestVersion, &manifest, &v.PackageDigest, &v.SigningKeyID, &v.Permissions, &v.Status,
		&v.UploadedByID, &v.ReviewedByID, &v.ReviewedAt, &v.ReviewNote, &v.InstalledAt, &v.CreatedAt, &v.manifestRaw, &v.payloadRaw, &v.signature)
	v.Manifest = manifest
	return &v, err
}

// Upload verifies a package and stores it as a new version awaiting review
// (or approved, when the realm policy allows single-administrator installs).
func (s *Service) Upload(ctx context.Context, realmID string, pkg Package, actor audit.Ref) (*Plugin, *Version, error) {
	if actor.Type != "user" {
		return nil, nil, problem.ErrForbidden.WithDetail("plugins are uploaded by an administrator account")
	}
	v, err := Verify(pkg, s.d.Cfg.Extensions.PluginPublishers, s.d.Now())
	if err != nil {
		return nil, nil, err
	}
	if err := s.check(ctx, realmID, v); err != nil {
		return nil, nil, err
	}
	if err := s.holdsAll(ctx, realmID, actor.ID, v.Manifest.Permissions); err != nil {
		return nil, nil, err
	}
	review := s.reviewMode(ctx, realmID)
	var plug *Plugin
	var ver *Version
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := scanPlugin(tx.QueryRow(ctx, `SELECT `+pluginCols+` FROM plugins WHERE realm_id=$1 AND name=$2 FOR UPDATE`, realmID, v.Manifest.Name))
		if storage.IsNoRows(err) {
			id := ids.New("plg")
			if _, err := tx.Exec(ctx, `INSERT INTO plugins (id, realm_id, name, publisher, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$5)`, id, realmID,
				v.Manifest.Name, v.Manifest.Publisher, s.d.Now()); err != nil {
				return err
			}
			p, err = scanPlugin(tx.QueryRow(ctx, `SELECT `+pluginCols+` FROM plugins WHERE id=$1`, id))
		}
		if err != nil {
			return err
		}
		// A plugin name belongs to its publisher: another publisher's key can
		// never ship versions of it.
		if p.Publisher != v.Manifest.Publisher {
			return problem.ErrConflict.WithDetail("a plugin with this name from another publisher is installed")
		}
		status, reviewer, note := "pending_review", "", ""
		var reviewedAt *time.Time
		if review == realm.PluginReviewSingleAdmin {
			now := s.d.Now()
			status, reviewer, note, reviewedAt = "approved", actor.ID, "realm policy plugin_review=single_admin", &now
		}
		id := ids.New("pgv")
		if _, err := tx.Exec(ctx, `INSERT INTO plugin_versions (id, realm_id, plugin_id, version, manifest_version, manifest, manifest_raw, payload_raw,
			package_digest, signing_key_id, signature, permissions, status, uploaded_by_id, reviewed_by_id, reviewed_at, review_note, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, id, realmID, p.ID, v.Manifest.Version, v.Manifest.ManifestVersion,
			v.ManifestRaw, v.ManifestRaw, v.PayloadRaw, v.Digest, v.KeyID, v.Signature, v.Manifest.Permissions, status, actor.ID, nilIfEmpty(reviewer),
			reviewedAt, nilIfEmpty(note), s.d.Now()); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("manifest.version", "this version was already uploaded")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "plugin.version.uploaded", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "plugin", ID: p.ID}, Metadata: map[string]any{"name": v.Manifest.Name, "version": v.Manifest.Version,
				"publisher": v.Manifest.Publisher, "signing_key_id": v.KeyID, "package_digest": v.Digest, "permissions": v.Manifest.Permissions,
				"hooks": len(v.Payload.Hooks), "webhooks": len(v.Payload.Webhooks), "workflows": len(v.Payload.Workflows), "review": review}}); err != nil {
			return err
		}
		plug = p
		ver, err = scanVersion(tx.QueryRow(ctx, `SELECT `+versionCols+` FROM plugin_versions WHERE id=$1`, id))
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return plug, ver, nil
}

func (s *Service) reviewMode(ctx context.Context, realmID string) string {
	if s.Realms != nil {
		if r, err := s.Realms.ByID(ctx, nil, realmID); err == nil {
			return r.Policy.Extensions.PluginReviewMode()
		}
	}
	return realm.PluginReviewSecondAdmin
}

// check validates every part with the API's own validation and the manifest's
// declared permissions against what the parts need (EXT-014).
func (s *Service) check(ctx context.Context, realmID string, v *Verified) error {
	names := map[string]map[string]bool{"hooks": {}, "webhooks": {}, "workflows": {}}
	unique := func(kind, name string, i int) error {
		if names[kind][name] {
			return invalid(fmt.Sprintf("payload.%s[%d].name", kind, i), "names must be unique within a plugin")
		}
		names[kind][name] = true
		return nil
	}
	for i, h := range v.Payload.Hooks {
		in := h
		if in.OwnerUserID != "" {
			return invalid(fmt.Sprintf("payload.hooks[%d].owner_user_id", i), "the installing administrator owns plugin parts")
		}
		if err := s.Hooks.Validate(&in); err != nil {
			return prefix(err, fmt.Sprintf("payload.hooks[%d]", i))
		}
		if req := v.Manifest.Requires["hook_contract"]; len(req) > 0 && !slices.Contains(req, in.ContractVersion) {
			return invalid(fmt.Sprintf("payload.hooks[%d].contract_version", i), "not among the manifest's requires.hook_contract")
		}
		if err := unique("hooks", in.Name, i); err != nil {
			return err
		}
	}
	for i, w := range v.Payload.Webhooks {
		in := w
		if in.OrganizationID != "" {
			return invalid(fmt.Sprintf("payload.webhooks[%d].organization_id", i), "plugin subscriptions are realm-wide")
		}
		if err := s.Webhooks.Validate(&in); err != nil {
			return prefix(err, fmt.Sprintf("payload.webhooks[%d]", i))
		}
		if req := v.Manifest.Requires["webhook_events"]; len(req) > 0 && !slices.Contains(req, in.EventVersion) {
			return invalid(fmt.Sprintf("payload.webhooks[%d].event_version", i), "not among the manifest's requires.webhook_events")
		}
		if err := unique("webhooks", in.Name, i); err != nil {
			return err
		}
	}
	for i, w := range v.Payload.Workflows {
		if err := unique("workflows", w.Name, i); err != nil {
			return err
		}
	}
	required, err := requiredPermissions(v.Payload, func(w WorkflowPart) ([]string, error) {
		def, err := s.Workflows.ValidateDefinition(ctx, realmID, w.Definition)
		if err != nil {
			return nil, prefix(err, "payload.workflows["+w.Name+"]")
		}
		if req := v.Manifest.Requires["workflow_definition"]; len(req) > 0 && !slices.Contains(req, def.SchemaVersion) {
			return nil, invalid("payload.workflows["+w.Name+"].definition.schema_version", "not among the manifest's requires.workflow_definition")
		}
		return def.Permissions(), nil
	})
	if err != nil {
		return err
	}
	var missing []string
	for _, p := range required {
		if !slices.Contains(v.Manifest.Permissions, p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return problem.ErrValidation.WithField("manifest.permissions", fmt.Sprintf("the parts need undeclared permissions: %v", missing))
	}
	return nil
}

// prefix rewrites a part's validation error to point into the payload.
func prefix(err error, at string) error {
	pe, ok := problem.As(err)
	if !ok || len(pe.Fields) == 0 {
		return err
	}
	out := problem.ErrValidation.WithDetail(pe.Detail)
	for k, v := range pe.Fields {
		out = out.WithField(at+"."+k, v)
	}
	return out
}

// holdsAll requires an administrator to hold every declared permission: a
// plugin never carries capabilities its uploader, reviewer or installer
// could not use directly (delegation ceiling, AZ-006).
func (s *Service) holdsAll(ctx context.Context, realmID, userID string, perms []string) error {
	eff, err := s.Authz.Effective(ctx, nil, realmID, authorization.Subject{Type: authorization.SubjectUser, ID: userID},
		authorization.Scope{Type: authorization.ScopeRealm, ID: realmID})
	if err != nil {
		return err
	}
	var missing []string
	for _, p := range perms {
		if !eff.Has(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return problem.ErrGrantCeiling.WithDetailf("the plugin declares permissions you do not hold: %v", missing)
	}
	return nil
}

func (s *Service) lock(ctx context.Context, tx pgx.Tx, realmID, id string) (*Plugin, error) {
	p, err := scanPlugin(tx.QueryRow(ctx, `SELECT `+pluginCols+` FROM plugins WHERE realm_id=$1 AND (id=$2 OR name=$2) FOR UPDATE`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return p, err
}

func (s *Service) version(ctx context.Context, q storage.Querier, pluginID, version string) (*Version, error) {
	v, err := scanVersion(q.QueryRow(ctx, `SELECT `+versionCols+` FROM plugin_versions WHERE plugin_id=$1 AND version=$2`, pluginID, version))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return v, err
}

// Review approves or rejects a version awaiting review. The reviewer is not
// the uploader and holds every permission the plugin declares.
func (s *Service) Review(ctx context.Context, realmID, id, version string, approve bool, note string, actor audit.Ref) (*Version, error) {
	if len(note) > 500 {
		return nil, problem.ErrValidation.WithField("note", "at most 500 characters")
	}
	var out *Version
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		v, err := s.version(ctx, tx, p.ID, version)
		if err != nil {
			return err
		}
		if v.Status != "pending_review" {
			return problem.ErrConflict.WithDetail("only versions awaiting review can be reviewed")
		}
		if v.UploadedByID == actor.ID {
			return problem.ErrForbidden.WithDetail("a second administrator must review the version (self-approval is not permitted)")
		}
		if approve {
			if err := s.holdsAll(ctx, realmID, actor.ID, v.Permissions); err != nil {
				return err
			}
		}
		status, event := "approved", "plugin.version.approved"
		if !approve {
			status, event = "rejected", "plugin.version.rejected"
		}
		if _, err := tx.Exec(ctx, `UPDATE plugin_versions SET status=$2, reviewed_by_id=$3, reviewed_at=$4, review_note=$5 WHERE id=$1`, v.ID, status,
			actor.ID, s.d.Now(), nilIfEmpty(note)); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: event, RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "plugin", ID: p.ID}, Metadata: map[string]any{"name": p.Name, "version": version, "package_digest": v.PackageDigest,
				"uploaded_by": v.UploadedByID, "permissions": v.Permissions}}); err != nil {
			return err
		}
		out, err = s.version(ctx, tx, p.ID, version)
		return err
	})
	return out, err
}

// InstallResult reports an installation and the one-time signing secrets of
// parts it created.
type InstallResult struct {
	Plugin  *Plugin      `json:"plugin"`
	Secrets []PartSecret `json:"signing_secrets"`
}

// PartSecret is the signing secret of a part an installation created; it is
// shown once, like the secret of a hook or subscription created through the
// API. Parts kept from an earlier version keep their secrets.
type PartSecret struct {
	Kind   string `json:"kind"`
	PartID string `json:"part_id"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

// Install installs, upgrades to or rolls back to a version. Upgrades and
// rollbacks reconcile parts by name: existing parts keep their identity and
// signing secrets, parts the version drops are removed. A version that was
// installed before (a rollback target) needs no new review.
func (s *Service) Install(ctx context.Context, realmID, id, version string, actor audit.Ref) (*InstallResult, error) {
	return s.install(ctx, realmID, id, version, actor, "")
}

func (s *Service) install(ctx context.Context, realmID, id, version string, actor audit.Ref, mode string) (*InstallResult, error) {
	if actor.Type != "user" {
		return nil, problem.ErrForbidden.WithDetail("plugins are installed by an administrator account")
	}
	out := &InstallResult{Secrets: []PartSecret{}}
	var pluginID string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		pluginID = p.ID
		if mode == "rollback" {
			if p.PreviousVersion == "" {
				return problem.ErrConflict.WithDetail("there is no previous version to roll back to")
			}
			version = p.PreviousVersion
		}
		v, err := s.version(ctx, tx, p.ID, version)
		if err != nil {
			return err
		}
		switch v.Status {
		case "approved", "superseded":
			if v.Status == "superseded" && v.InstalledAt == nil {
				return problem.ErrConflict.WithDetail("the version was never installed")
			}
		case "installed":
			if p.InstalledVersion == version {
				return problem.ErrConflict.WithDetail("this version is already installed")
			}
		case "pending_review":
			return problem.ErrForbidden.WithDetail("the version awaits review by a second administrator")
		default:
			return problem.ErrConflict.WithDetail("the version was " + v.Status)
		}
		// Trust and compatibility are re-established at installation: a
		// publisher key removed from configuration, or a server that no
		// longer supports a required contract, stops the installation.
		ver, err := Verify(Package{Manifest: b64(v.manifestRaw), Payload: b64(v.payloadRaw), Signature: Signature{KeyID: v.SigningKeyID,
			Algorithm: "Ed25519", Value: v.signature}}, s.d.Cfg.Extensions.PluginPublishers, s.d.Now())
		if err != nil {
			return err
		}
		if err := s.check(ctx, realmID, ver); err != nil {
			return err
		}
		if err := s.holdsAll(ctx, realmID, actor.ID, v.Permissions); err != nil {
			return err
		}
		if err := s.checkDependencies(ctx, tx, realmID, ver.Manifest); err != nil {
			return err
		}
		// A downgrade or rollback must still satisfy every enabled plugin
		// that depends on this one.
		if err := s.checkDependents(ctx, tx, realmID, p.Name, version); err != nil {
			return err
		}
		reviewer := v.ReviewedByID
		keep := map[string][]string{}
		for _, h := range ver.Payload.Hooks {
			hid, sec, err := s.Hooks.ApplyPluginTx(ctx, tx, realmID, p.ID, h, actor)
			if err != nil {
				return prefix(err, "payload.hooks")
			}
			if sec != "" {
				out.Secrets = append(out.Secrets, PartSecret{Kind: "hook", PartID: hid, Name: h.Name, Secret: sec})
			}
			keep["hooks"] = append(keep["hooks"], h.Name)
		}
		for _, w := range ver.Payload.Webhooks {
			wid, sec, err := s.Webhooks.ApplyPluginTx(ctx, tx, realmID, p.ID, w, actor)
			if err != nil {
				return prefix(err, "payload.webhooks")
			}
			if sec != "" {
				out.Secrets = append(out.Secrets, PartSecret{Kind: "webhook", PartID: wid, Name: w.Name, Secret: sec})
			}
			keep["webhooks"] = append(keep["webhooks"], w.Name)
		}
		for _, w := range ver.Payload.Workflows {
			if _, err := s.Workflows.ApplyPluginTx(ctx, tx, realmID, p.ID, w.Name, w.Description, w.Definition, reviewer, true, actor); err != nil {
				return prefix(err, "payload.workflows")
			}
			keep["workflows"] = append(keep["workflows"], w.Name)
		}
		if _, err := s.Hooks.RemovePluginPartsTx(ctx, tx, realmID, p.ID, keep["hooks"], actor); err != nil {
			return err
		}
		if _, err := s.Webhooks.RemovePluginPartsTx(ctx, tx, realmID, p.ID, keep["webhooks"], actor); err != nil {
			return err
		}
		if _, err := s.Workflows.RemovePluginPartsTx(ctx, tx, realmID, p.ID, keep["workflows"], actor); err != nil {
			return err
		}
		// Each part now has the state its version declares (ApplyPluginTx);
		// parts an administrator switched off in an emergency stay off.
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE plugin_versions SET status='superseded' WHERE plugin_id=$1 AND status='installed'`, p.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE plugin_versions SET status='installed', installed_at=$2 WHERE id=$1`, v.ID, now); err != nil {
			return err
		}
		previous := p.InstalledVersion
		if previous == version {
			previous = p.PreviousVersion
		}
		if _, err := tx.Exec(ctx, `UPDATE plugins SET state='enabled', installed_version=$2, previous_version=$3, installed_by_id=$4, installed_at=$5,
			version=version+1, updated_at=$5 WHERE id=$1`, p.ID, version, nilIfEmpty(previous), actor.ID, now); err != nil {
			return err
		}
		event := "plugin.installed"
		switch {
		case mode == "rollback":
			event = "plugin.rolled_back"
		case p.InstalledVersion != "":
			event = "plugin.upgraded"
			if a, ok1 := ParseSemver(p.InstalledVersion); ok1 {
				if b, ok2 := ParseSemver(version); ok2 && b.Less(a) {
					event = "plugin.downgraded"
				}
			}
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: event, RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "plugin", ID: p.ID}, Metadata: map[string]any{"name": p.Name, "version": version, "from_version": p.InstalledVersion,
				"package_digest": v.PackageDigest, "reviewed_by": reviewer, "review": s.reviewMode(ctx, realmID), "hooks": keep["hooks"],
				"webhooks": keep["webhooks"], "workflows": keep["workflows"]}})
		return err
	})
	if err != nil {
		return nil, err
	}
	out.Plugin, err = s.Get(ctx, realmID, pluginID)
	return out, err
}

// Rollback reinstalls the previously installed version.
func (s *Service) Rollback(ctx context.Context, realmID, id string, actor audit.Ref) (*InstallResult, error) {
	return s.install(ctx, realmID, id, "", actor, "rollback")
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// checkDependencies requires every dependency installed, enabled and at
// least at its minimum version.
func (s *Service) checkDependencies(ctx context.Context, tx pgx.Tx, realmID string, m Manifest) error {
	for _, d := range m.Dependencies {
		var state, installed string
		err := tx.QueryRow(ctx, `SELECT state, coalesce(installed_version,'') FROM plugins WHERE realm_id=$1 AND name=$2`, realmID, d.Name).Scan(&state, &installed)
		if storage.IsNoRows(err) || err == nil && (state != "enabled" || installed == "") {
			return problem.ErrConflict.WithDetailf("requires plugin %s %s or later, installed and enabled", d.Name, d.MinVersion).
				WithExtension("missing_dependency", d.Name)
		}
		if err != nil {
			return err
		}
		have, _ := ParseSemver(installed)
		want, _ := ParseSemver(d.MinVersion)
		if have.Less(want) {
			return problem.ErrConflict.WithDetailf("requires plugin %s %s or later; %s is installed", d.Name, d.MinVersion, installed).
				WithExtension("missing_dependency", d.Name)
		}
	}
	return nil
}

// checkDependents refuses installing a version of name lower than an
// enabled dependent plugin requires.
func (s *Service) checkDependents(ctx context.Context, tx pgx.Tx, realmID, name, version string) error {
	rows, err := tx.Query(ctx, `SELECT p.name, v.manifest FROM plugins p JOIN plugin_versions v ON v.plugin_id=p.id AND v.version=p.installed_version
		WHERE p.realm_id=$1 AND p.state='enabled' AND p.name<>$2`, realmID, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	next, _ := ParseSemver(version)
	for rows.Next() {
		var n string
		var raw []byte
		if err := rows.Scan(&n, &raw); err != nil {
			return err
		}
		var m Manifest
		_ = json.Unmarshal(raw, &m)
		for _, d := range m.Dependencies {
			if d.Name != name {
				continue
			}
			if want, _ := ParseSemver(d.MinVersion); next.Less(want) {
				return problem.ErrConflict.WithDetailf("enabled plugin %s requires %s %s or later", n, name, d.MinVersion).
					WithExtension("dependent", n)
			}
		}
	}
	return rows.Err()
}

// applyDeclaredHookStatesTx turns off the hooks a version's payload declares
// disabled, after the plugin's parts were switched on.
func (s *Service) applyDeclaredHookStatesTx(ctx context.Context, tx pgx.Tx, realmID, pluginID, version string) error {
	v, err := s.version(ctx, tx, pluginID, version)
	if err != nil {
		return err
	}
	var payload Payload
	if err := json.Unmarshal(v.payloadRaw, &payload); err != nil {
		return err
	}
	var off []string
	for _, h := range payload.Hooks {
		if h.State == "disabled" {
			off = append(off, h.Name)
		}
	}
	if len(off) == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, `UPDATE hooks SET state='disabled', version=version+1, updated_at=$4 WHERE realm_id=$1 AND plugin_id=$2 AND name = ANY($3)
		AND state<>'disabled'`, realmID, pluginID, off, s.d.Now())
	return err
}

// dependents lists enabled plugins that depend on name.
func (s *Service) dependents(ctx context.Context, tx pgx.Tx, realmID, name string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT p.name, v.manifest FROM plugins p JOIN plugin_versions v ON v.plugin_id=p.id AND v.version=p.installed_version
		WHERE p.realm_id=$1 AND p.state='enabled' AND p.name<>$2`, realmID, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		var raw []byte
		if err := rows.Scan(&n, &raw); err != nil {
			return nil, err
		}
		var m Manifest
		_ = json.Unmarshal(raw, &m)
		for _, d := range m.Dependencies {
			if d.Name == name {
				out = append(out, n)
			}
		}
	}
	return out, rows.Err()
}

func (s *Service) setPartsTx(ctx context.Context, tx pgx.Tx, realmID, pluginID, state string) error {
	if _, err := s.Hooks.SetPluginStateTx(ctx, tx, realmID, pluginID, state); err != nil {
		return err
	}
	if _, err := s.Webhooks.SetPluginStateTx(ctx, tx, realmID, pluginID, state); err != nil {
		return err
	}
	_, err := s.Workflows.SetPluginStateTx(ctx, tx, realmID, pluginID, state)
	return err
}

// SetState enables or disables a plugin: every hook, subscription and
// workflow it manages changes state in one transaction (EXT-014). Disabling
// is refused while an enabled plugin depends on it; it is recorded as an
// emergency control (SEC-020) because it stops security decisions the
// plugin's hooks were making.
func (s *Service) SetState(ctx context.Context, realmID, id, state, reason string, actor audit.Ref) (*Plugin, error) {
	if state != "enabled" && state != "disabled" {
		return nil, problem.ErrValidation.WithField("state", "enabled or disabled")
	}
	var pluginID string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		pluginID = p.ID
		if p.InstalledVersion == "" {
			return problem.ErrConflict.WithDetail("the plugin is not installed")
		}
		if p.State == state {
			return nil
		}
		if state == "disabled" {
			deps, err := s.dependents(ctx, tx, realmID, p.Name)
			if err != nil {
				return err
			}
			if len(deps) > 0 {
				return problem.ErrConflict.WithDetailf("enabled plugins depend on it: %v; disable them first", deps)
			}
		} else {
			// Enabling re-establishes trust like an installation: the
			// publisher key must still be configured, the contracts still
			// supported, and the administrator must hold every permission
			// the plugin declares.
			if actor.Type != "user" {
				return problem.ErrForbidden.WithDetail("plugins are enabled by an administrator account")
			}
			v, err := s.version(ctx, tx, p.ID, p.InstalledVersion)
			if err != nil {
				return err
			}
			ver, err := Verify(Package{Manifest: b64(v.manifestRaw), Payload: b64(v.payloadRaw), Signature: Signature{KeyID: v.SigningKeyID,
				Algorithm: "Ed25519", Value: v.signature}}, s.d.Cfg.Extensions.PluginPublishers, s.d.Now())
			if err != nil {
				return err
			}
			if err := s.check(ctx, realmID, ver); err != nil {
				return err
			}
			if err := s.holdsAll(ctx, realmID, actor.ID, v.Permissions); err != nil {
				return err
			}
			if err := s.checkDependencies(ctx, tx, realmID, ver.Manifest); err != nil {
				return err
			}
		}
		parts := map[string]string{"enabled": "active", "disabled": "disabled"}[state]
		if err := s.setPartsTx(ctx, tx, realmID, p.ID, parts); err != nil {
			return err
		}
		if state == "enabled" {
			// Hooks the version declares disabled stay disabled.
			if err := s.applyDeclaredHookStatesTx(ctx, tx, realmID, p.ID, p.InstalledVersion); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE plugins SET state=$2, version=version+1, updated_at=$3 WHERE id=$1`, p.ID, state, s.d.Now()); err != nil {
			return err
		}
		category := "configuration"
		if state == "disabled" {
			category = "emergency"
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "plugin." + state, RealmID: realmID, Actor: actor, Category: category, ReasonCode: reason,
			Target: &audit.Ref{Type: "plugin", ID: p.ID}, Metadata: map[string]any{"name": p.Name, "version": p.InstalledVersion}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, realmID, pluginID)
}

// Uninstall removes every part; workflows that ran stay, disabled, as
// evidence. Stored versions remain for audit and reinstallation.
func (s *Service) Uninstall(ctx context.Context, realmID, id string, actor audit.Ref) (*Plugin, error) {
	var pluginID string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		pluginID = p.ID
		if p.InstalledVersion == "" {
			return problem.ErrConflict.WithDetail("the plugin is not installed")
		}
		deps, err := s.dependents(ctx, tx, realmID, p.Name)
		if err != nil {
			return err
		}
		if len(deps) > 0 {
			return problem.ErrConflict.WithDetailf("enabled plugins depend on it: %v; disable them first", deps)
		}
		h, err := s.Hooks.RemovePluginPartsTx(ctx, tx, realmID, p.ID, nil, actor)
		if err != nil {
			return err
		}
		w, err := s.Webhooks.RemovePluginPartsTx(ctx, tx, realmID, p.ID, nil, actor)
		if err != nil {
			return err
		}
		wf, err := s.Workflows.RemovePluginPartsTx(ctx, tx, realmID, p.ID, nil, actor)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE plugin_versions SET status='superseded' WHERE plugin_id=$1 AND status='installed'`, p.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE plugins SET state='inactive', installed_version=NULL, previous_version=$2, version=version+1, updated_at=$3
			WHERE id=$1`, p.ID, p.InstalledVersion, s.d.Now()); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "plugin.uninstalled", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "plugin", ID: p.ID}, Metadata: map[string]any{"name": p.Name, "version": p.InstalledVersion,
				"hooks_removed": len(h), "webhooks_removed": len(w), "workflows_removed": len(wf)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, realmID, pluginID)
}

// Get returns a plugin with its parts.
func (s *Service) Get(ctx context.Context, realmID, id string) (*Plugin, error) {
	p, err := scanPlugin(s.d.DB.Pool.QueryRow(ctx, `SELECT `+pluginCols+` FROM plugins WHERE realm_id=$1 AND (id=$2 OR name=$2)`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Parts = &Parts{Hooks: []PartRef{}, Webhooks: []PartRef{}, Workflows: []PartRef{}}
	for _, q := range []struct {
		sql  string
		into *[]PartRef
	}{
		{`SELECT id, name, state FROM hooks WHERE realm_id=$1 AND plugin_id=$2 ORDER BY name`, &p.Parts.Hooks},
		{`SELECT id, name, state FROM webhook_subscriptions WHERE realm_id=$1 AND plugin_id=$2 ORDER BY name`, &p.Parts.Webhooks},
		{`SELECT id, name, state FROM workflows WHERE realm_id=$1 AND plugin_id=$2 ORDER BY name`, &p.Parts.Workflows},
	} {
		rows, err := s.d.DB.Pool.Query(ctx, q.sql, realmID, p.ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r PartRef
			if err := rows.Scan(&r.ID, &r.Name, &r.State); err != nil {
				rows.Close()
				return nil, err
			}
			*q.into = append(*q.into, r)
		}
		rows.Close()
	}
	return p, nil
}

// List returns a realm's plugins.
func (s *Service) List(ctx context.Context, realmID string) ([]*Plugin, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+pluginCols+` FROM plugins WHERE realm_id=$1 ORDER BY name LIMIT 500`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Plugin{}
	for rows.Next() {
		p, err := scanPlugin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Versions lists a plugin's versions, newest first (manifests only).
func (s *Service) Versions(ctx context.Context, realmID, id string) ([]*Version, error) {
	p, err := s.Get(ctx, realmID, id)
	if err != nil {
		return nil, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+versionCols+` FROM plugin_versions WHERE plugin_id=$1 ORDER BY created_at DESC LIMIT 200`, p.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Version{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVersion returns one version with its payload, for review.
func (s *Service) GetVersion(ctx context.Context, realmID, id, version string) (*Version, error) {
	p, err := s.Get(ctx, realmID, id)
	if err != nil {
		return nil, err
	}
	v, err := s.version(ctx, s.d.DB.Pool, p.ID, version)
	if err != nil {
		return nil, err
	}
	if json.Valid(v.payloadRaw) {
		v.Payload = v.payloadRaw
	}
	return v, nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
