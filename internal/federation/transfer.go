package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// Federation transfer (FED-016) moves account links from one provider
// connection to another through a reviewed migration map: each entry names
// the subject at the source and the subject the same person has at the
// target. Analysis reports missing sources and collisions; a second
// administrator approves; apply moves only entries that are still ready.
// Email addresses never decide who is relinked.

// Transfer entry outcomes.
const (
	TransferReady              = "ready"
	TransferAlreadyLinked      = "already_linked"   // the target link exists for the same account
	TransferMissingSource      = "missing_source"   // no link at the source for this subject
	TransferAmbiguousSource    = "ambiguous_source" // the subject is linked under several source issuers; name source_issuer
	TransferDuplicateSource    = "duplicate_source" // the map names this source twice
	TransferDuplicateTarget    = "duplicate_target" // the map gives two sources the same target
	TransferTargetLinked       = "collision_target" // the target subject is linked to another account
	TransferUserHasTarget      = "collision_user"   // the account already has another link at the target
	TransferTenantRequired     = "target_tenant_required"
	TransferApplied            = "applied"
	maxTransferEntries         = 50000
	maxTransferEntriesPerBatch = 2000
)

// TransferEntry is one row of the migration map.
type TransferEntry struct {
	Seq           int    `json:"seq"`
	SourceSubject string `json:"source_subject"`
	SourceIssuer  string `json:"source_issuer,omitempty"`
	TargetSubject string `json:"target_subject"`
	TargetTenant  string `json:"target_tenant,omitempty"`
	UserID        string `json:"user_id,omitempty"`
	Outcome       string `json:"outcome"`
	Detail        string `json:"detail,omitempty"`
}

// Transfer is a federation transfer plan.
type Transfer struct {
	ID               string         `json:"id"`
	SourceProviderID string         `json:"source_provider_id"`
	TargetProviderID string         `json:"target_provider_id"`
	Mode             string         `json:"mode"`
	TargetTenant     string         `json:"target_tenant,omitempty"`
	State            string         `json:"state"`
	Reason           string         `json:"reason"`
	Summary          map[string]int `json:"summary"`
	CreatedByID      string         `json:"created_by_id"`
	ApprovedByID     string         `json:"approved_by_id,omitempty"`
	AppliedByID      string         `json:"applied_by_id,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	ApprovedAt       *time.Time     `json:"approved_at,omitempty"`
	AppliedAt        *time.Time     `json:"applied_at,omitempty"`
	Version          int64          `json:"version"`
}

// TransferInput creates a plan. Mode map takes entries (more can be added
// while the plan is a draft); mode same_subject maps every source link to
// the same subject at the target (an upstream tenant move that keeps
// subjects), with target_tenant for a multi-tenant target issuer.
type TransferInput struct {
	SourceProviderID string          `json:"source_provider_id"`
	TargetProviderID string          `json:"target_provider_id"`
	Mode             string          `json:"mode"`
	TargetTenant     string          `json:"target_tenant"`
	Reason           string          `json:"reason"`
	Entries          []TransferEntry `json:"entries"`
}

const transferCols = `id, source_provider_id, target_provider_id, mode, coalesce(target_tenant,''), state, reason, summary, created_by_id,
	coalesce(approved_by_id,''), coalesce(applied_by_id,''), created_at, approved_at, applied_at, version`

func scanTransfer(row pgx.Row) (*Transfer, error) {
	var t Transfer
	var summary []byte
	if err := row.Scan(&t.ID, &t.SourceProviderID, &t.TargetProviderID, &t.Mode, &t.TargetTenant, &t.State, &t.Reason, &summary, &t.CreatedByID,
		&t.ApprovedByID, &t.AppliedByID, &t.CreatedAt, &t.ApprovedAt, &t.AppliedAt, &t.Version); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(summary, &t.Summary)
	return &t, nil
}

// Transfer returns a plan.
func (s *Service) Transfer(ctx context.Context, realmID, id string) (*Transfer, error) {
	return scanTransfer(s.d.DB.Pool.QueryRow(ctx, `SELECT `+transferCols+` FROM federation_transfers WHERE realm_id=$1 AND id=$2`, realmID, id))
}

// Transfers lists plans, newest first.
func (s *Service) Transfers(ctx context.Context, realmID string) ([]*Transfer, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+transferCols+` FROM federation_transfers WHERE realm_id=$1 ORDER BY created_at DESC LIMIT 200`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Transfer{}
	for rows.Next() {
		t, err := scanTransfer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TransferEntries lists a plan's entries, optionally of one outcome.
func (s *Service) TransferEntries(ctx context.Context, realmID, id, outcome string, after, limit int) ([]TransferEntry, error) {
	if _, err := s.Transfer(ctx, realmID, id); err != nil {
		return nil, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT seq, source_subject, coalesce(source_issuer,''), target_subject, coalesce(target_tenant,''),
		coalesce(user_id,''), outcome, coalesce(detail,'') FROM federation_transfer_entries WHERE transfer_id=$1 AND ($2='' OR outcome=$2) AND seq > $3
		ORDER BY seq LIMIT $4`, id, outcome, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TransferEntry{}
	for rows.Next() {
		var e TransferEntry
		if err := rows.Scan(&e.Seq, &e.SourceSubject, &e.SourceIssuer, &e.TargetSubject, &e.TargetTenant, &e.UserID, &e.Outcome, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func validEntry(e TransferEntry) bool {
	ok := func(v string, max int) bool { return v != "" && len(v) <= max && !strings.ContainsAny(v, "\x00\r\n") }
	return ok(e.SourceSubject, 255) && ok(e.TargetSubject, 255) && len(e.SourceIssuer) <= 512 && len(e.TargetTenant) <= 128
}

// CreateTransfer saves a draft plan and analyses it.
func (s *Service) CreateTransfer(ctx context.Context, realmID string, in TransferInput, actor audit.Ref) (*Transfer, error) {
	if in.Reason == "" || len(in.Reason) > 500 {
		return nil, problem.ErrValidation.WithField("reason", "1 to 500 characters")
	}
	if in.Mode != "map" && in.Mode != "same_subject" {
		return nil, problem.ErrValidation.WithField("mode", "map or same_subject")
	}
	if in.Mode == "same_subject" && len(in.Entries) > 0 {
		return nil, problem.ErrValidation.WithField("entries", "same_subject derives the entries from the source links")
	}
	if len(in.Entries) > maxTransferEntriesPerBatch {
		return nil, problem.ErrValidation.WithField("entries", fmt.Sprintf("at most %d entries per request; add more to the draft", maxTransferEntriesPerBatch))
	}
	id := ids.New("fxt")
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		src, err := s.Get(ctx, tx, realmID, in.SourceProviderID)
		if err != nil {
			return problem.ErrValidation.WithField("source_provider_id", "an identity provider of this realm")
		}
		dst, err := s.Get(ctx, tx, realmID, in.TargetProviderID)
		if err != nil {
			return problem.ErrValidation.WithField("target_provider_id", "an identity provider of this realm")
		}
		switch {
		case src.ID == dst.ID:
			return problem.ErrValidation.WithField("target_provider_id", "a different connection; for a new upstream tenant create a connection with the new issuer")
		case src.OrganizationID != dst.OrganizationID:
			return problem.ErrValidation.WithField("target_provider_id", "a connection of the same organization (or both realm-wide)")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO federation_transfers (id, realm_id, source_provider_id, target_provider_id, mode, target_tenant, state,
			reason, created_by_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,'draft',$7,$8,$9)`,
			id, realmID, src.ID, dst.ID, in.Mode, nilIfEmpty(in.TargetTenant), in.Reason, actor.ID, s.d.Now()); err != nil {
			return err
		}
		entries := in.Entries
		if in.Mode == "same_subject" {
			if entries, err = sameSubjectEntries(ctx, tx, realmID, src.ID, in.TargetTenant); err != nil {
				return err
			}
		}
		if err := insertEntries(ctx, tx, id, 0, entries); err != nil {
			return err
		}
		if _, err := s.analyzeTx(ctx, tx, realmID, id); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.transfer.created", RealmID: realmID, Actor: actor, OrgID: src.OrganizationID,
			Target: &audit.Ref{Type: "federation_transfer", ID: id}, ReasonCode: in.Reason, Category: "security",
			Metadata: map[string]any{"source_provider": src.Alias, "target_provider": dst.Alias, "mode": in.Mode, "entries": len(entries)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Transfer(ctx, realmID, id)
}

func sameSubjectEntries(ctx context.Context, tx pgx.Tx, realmID, providerID, tenant string) ([]TransferEntry, error) {
	rows, err := tx.Query(ctx, `SELECT upstream_subject, upstream_issuer FROM external_identities WHERE realm_id=$1 AND provider_id=$2
		ORDER BY created_at, id LIMIT $3`, realmID, providerID, maxTransferEntries+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TransferEntry
	for rows.Next() {
		var e TransferEntry
		if err := rows.Scan(&e.SourceSubject, &e.SourceIssuer); err != nil {
			return nil, err
		}
		e.TargetSubject, e.TargetTenant = e.SourceSubject, tenant
		out = append(out, e)
	}
	if len(out) > maxTransferEntries {
		return nil, problem.ErrValidation.WithField("source_provider_id", fmt.Sprintf("more than %d links; transfer with explicit maps", maxTransferEntries))
	}
	return out, rows.Err()
}

func insertEntries(ctx context.Context, tx pgx.Tx, id string, start int, entries []TransferEntry) error {
	for i, e := range entries {
		if !validEntry(e) {
			return problem.ErrValidation.WithField(fmt.Sprintf("entries[%d]", i), "source_subject and target_subject are required, single-line, at most 255 characters")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO federation_transfer_entries (transfer_id, seq, source_subject, source_issuer, target_subject, target_tenant, outcome)
			VALUES ($1,$2,$3,$4,$5,$6,'pending')`, id, start+i+1, e.SourceSubject, nilIfEmpty(e.SourceIssuer), e.TargetSubject, nilIfEmpty(e.TargetTenant)); err != nil {
			return err
		}
	}
	return nil
}

// AddTransferEntries appends map entries to a draft and analyses again.
func (s *Service) AddTransferEntries(ctx context.Context, realmID, id string, entries []TransferEntry, actor audit.Ref) (*Transfer, error) {
	if len(entries) == 0 || len(entries) > maxTransferEntriesPerBatch {
		return nil, problem.ErrValidation.WithField("entries", fmt.Sprintf("1 to %d entries", maxTransferEntriesPerBatch))
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		t, err := scanTransfer(tx.QueryRow(ctx, `SELECT `+transferCols+` FROM federation_transfers WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return err
		}
		if t.State != "draft" || t.Mode != "map" {
			return problem.ErrConflict.WithDetail("entries can only be added to a draft map transfer")
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM federation_transfer_entries WHERE transfer_id=$1`, id).Scan(&n); err != nil {
			return err
		}
		if n+len(entries) > maxTransferEntries {
			return problem.ErrValidation.WithField("entries", fmt.Sprintf("at most %d entries per transfer", maxTransferEntries))
		}
		if err := insertEntries(ctx, tx, id, n, entries); err != nil {
			return err
		}
		_, err = s.analyzeTx(ctx, tx, realmID, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Transfer(ctx, realmID, id)
}

type linkRow struct {
	id, user, issuer string
}

// analyzeTx classifies every entry against the current links and stores
// the outcome and the summary. It returns the summary.
func (s *Service) analyzeTx(ctx context.Context, tx pgx.Tx, realmID, id string) (map[string]int, error) {
	t, err := scanTransfer(tx.QueryRow(ctx, `SELECT `+transferCols+` FROM federation_transfers WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	dst, err := s.Get(ctx, tx, realmID, t.TargetProviderID)
	if err != nil {
		return nil, err
	}
	// Current links of both connections, keyed by subject.
	load := func(provider string) (map[string][]linkRow, map[string]bool, error) {
		rows, err := tx.Query(ctx, `SELECT id, user_id, upstream_issuer, upstream_subject FROM external_identities WHERE realm_id=$1 AND provider_id=$2 FOR UPDATE`,
			realmID, provider)
		if err != nil {
			return nil, nil, err
		}
		defer rows.Close()
		bySubject, users := map[string][]linkRow{}, map[string]bool{}
		for rows.Next() {
			var l linkRow
			var sub string
			if err := rows.Scan(&l.id, &l.user, &l.issuer, &sub); err != nil {
				return nil, nil, err
			}
			bySubject[sub] = append(bySubject[sub], l)
			users[l.user] = true
		}
		return bySubject, users, rows.Err()
	}
	srcLinks, _, err := load(t.SourceProviderID)
	if err != nil {
		return nil, err
	}
	dstLinks, dstUsers, err := load(t.TargetProviderID)
	if err != nil {
		return nil, err
	}
	entries, err := s.allEntries(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	seenSource, seenTarget := map[string]int{}, map[string]int{}
	for _, e := range entries {
		seenSource[e.SourceSubject+"\x00"+e.SourceIssuer]++
		seenTarget[s.targetIssuer(dst, e.TargetTenant)+"\x00"+e.TargetSubject]++
	}
	type result struct{ outcome, detail, user string }
	results := make([]result, len(entries))
	readyUsers := map[string]int{}
	for i, e := range entries {
		if e.Outcome == TransferApplied {
			continue
		}
		o, d, u := s.classify(e, dst, srcLinks, dstLinks, dstUsers, seenSource, seenTarget)
		results[i] = result{o, d, u}
		if o == TransferReady {
			readyUsers[u]++
		}
	}
	summary := map[string]int{}
	for i, e := range entries {
		if e.Outcome == TransferApplied {
			summary[e.Outcome]++
			continue
		}
		r := results[i]
		if r.outcome == TransferReady && readyUsers[r.user] > 1 {
			// One account would end up with several links at the target.
			r.outcome, r.detail = TransferUserHasTarget, "several entries move the same account"
		}
		summary[r.outcome]++
		if _, err := tx.Exec(ctx, `UPDATE federation_transfer_entries SET outcome=$3, detail=$4, user_id=$5 WHERE transfer_id=$1 AND seq=$2`,
			id, e.Seq, r.outcome, nilIfEmpty(r.detail), nilIfEmpty(r.user)); err != nil {
			return nil, err
		}
	}
	summary["total"] = len(entries)
	doc, _ := json.Marshal(summary)
	if _, err := tx.Exec(ctx, `UPDATE federation_transfers SET summary=$2 WHERE id=$1`, id, doc); err != nil {
		return nil, err
	}
	return summary, nil
}

func (s *Service) allEntries(ctx context.Context, tx pgx.Tx, id string) ([]TransferEntry, error) {
	rows, err := tx.Query(ctx, `SELECT seq, source_subject, coalesce(source_issuer,''), target_subject, coalesce(target_tenant,''), outcome
		FROM federation_transfer_entries WHERE transfer_id=$1 ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TransferEntry
	for rows.Next() {
		var e TransferEntry
		if err := rows.Scan(&e.Seq, &e.SourceSubject, &e.SourceIssuer, &e.TargetSubject, &e.TargetTenant, &e.Outcome); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// targetIssuer is the issuer links at the target carry: the connection's
// issuer, with {tenant} substituted for multi-tenant connections.
func (s *Service) targetIssuer(dst *Provider, tenant string) string {
	if strings.Contains(dst.Issuer, "{tenant}") {
		if tenant == "" {
			return ""
		}
		return strings.ReplaceAll(dst.Issuer, "{tenant}", tenant)
	}
	return dst.Issuer
}

func (s *Service) classify(e TransferEntry, dst *Provider, srcLinks, dstLinks map[string][]linkRow, dstUsers map[string]bool,
	seenSource, seenTarget map[string]int) (outcome, detail, user string) {
	if seenSource[e.SourceSubject+"\x00"+e.SourceIssuer] > 1 {
		return TransferDuplicateSource, "", ""
	}
	issuer := s.targetIssuer(dst, e.TargetTenant)
	if issuer == "" {
		return TransferTenantRequired, "the target issuer is multi-tenant", ""
	}
	if seenTarget[issuer+"\x00"+e.TargetSubject] > 1 {
		return TransferDuplicateTarget, "", ""
	}
	var matches []linkRow
	for _, l := range srcLinks[e.SourceSubject] {
		if e.SourceIssuer == "" || l.issuer == e.SourceIssuer {
			matches = append(matches, l)
		}
	}
	switch len(matches) {
	case 0:
		return TransferMissingSource, "", ""
	case 1:
	default:
		return TransferAmbiguousSource, "", ""
	}
	user = matches[0].user
	for _, l := range dstLinks[e.TargetSubject] {
		if l.issuer != issuer {
			continue
		}
		if l.user == user {
			return TransferAlreadyLinked, "", user
		}
		return TransferTargetLinked, "the target subject is linked to another account", user
	}
	if dstUsers[user] {
		return TransferUserHasTarget, "the account already has a link at the target connection", user
	}
	return TransferReady, "", user
}

// ApproveTransfer records the review of a draft by an administrator other
// than its author. Analysis runs again, so the approver sees current
// collisions.
func (s *Service) ApproveTransfer(ctx context.Context, realmID, id string, expectedVersion int64, actor audit.Ref) (*Transfer, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		t, err := scanTransfer(tx.QueryRow(ctx, `SELECT `+transferCols+` FROM federation_transfers WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return err
		}
		if t.State != "draft" {
			return problem.ErrConflict.WithDetail("only a draft can be approved")
		}
		if expectedVersion != 0 && t.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		if actor.ID == t.CreatedByID {
			return problem.ErrForbidden.WithDetail("a transfer is approved by an administrator other than its author")
		}
		summary, err := s.analyzeTx(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if summary[TransferReady]+summary[TransferAlreadyLinked] == 0 {
			return problem.ErrConflict.WithDetail("nothing in this transfer can be applied")
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE federation_transfers SET state='approved', approved_by_id=$2, approved_at=$3, version=version+1 WHERE id=$1`,
			id, actor.ID, now); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.transfer.approved", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "federation_transfer", ID: id}, Category: "security", Metadata: map[string]any{"summary": summary}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Transfer(ctx, realmID, id)
}

// ApplyTransfer moves the links of entries that are still ready (analysis
// runs again under lock; anything that became a collision is skipped and
// reported). A link moves with its account: same link ID, new connection,
// issuer and subject; tokens kept for the old connection are discarded.
// Entries already linked at the target drop their source link.
func (s *Service) ApplyTransfer(ctx context.Context, realmID, id string, actor audit.Ref) (*Transfer, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		t, err := scanTransfer(tx.QueryRow(ctx, `SELECT `+transferCols+` FROM federation_transfers WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return err
		}
		if t.State != "approved" {
			return problem.ErrConflict.WithDetail("only an approved transfer can be applied")
		}
		dst, err := s.Get(ctx, tx, realmID, t.TargetProviderID)
		if err != nil {
			return err
		}
		if _, err := s.analyzeTx(ctx, tx, realmID, id); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT seq, source_subject, coalesce(source_issuer,''), target_subject, coalesce(target_tenant,''), user_id, outcome
			FROM federation_transfer_entries WHERE transfer_id=$1 AND outcome IN ('ready','already_linked') ORDER BY seq`, id)
		if err != nil {
			return err
		}
		var todo []TransferEntry
		for rows.Next() {
			var e TransferEntry
			if err := rows.Scan(&e.Seq, &e.SourceSubject, &e.SourceIssuer, &e.TargetSubject, &e.TargetTenant, &e.UserID, &e.Outcome); err != nil {
				rows.Close()
				return err
			}
			todo = append(todo, e)
		}
		rows.Close()
		now := s.d.Now()
		moved, dropped := 0, 0
		for _, e := range todo {
			srcIssuer := `AND ($4 = '' OR upstream_issuer = $4)`
			if e.Outcome == TransferAlreadyLinked {
				tag, err := tx.Exec(ctx, `DELETE FROM external_identities WHERE realm_id=$1 AND provider_id=$2 AND upstream_subject=$3 `+srcIssuer+` AND user_id=$5`,
					realmID, t.SourceProviderID, e.SourceSubject, e.SourceIssuer, e.UserID)
				if err != nil {
					return err
				}
				dropped += int(tag.RowsAffected())
			} else {
				tag, err := tx.Exec(ctx, `UPDATE external_identities SET provider_id=$6, upstream_issuer=$7, upstream_subject=$8, upstream_tenant=$9,
					linking_provenance='federation_transfer', upstream_token_ciphertext=NULL, key_version=NULL, mapping_revision=$10
					WHERE realm_id=$1 AND provider_id=$2 AND upstream_subject=$3 `+srcIssuer+` AND user_id=$5`,
					realmID, t.SourceProviderID, e.SourceSubject, e.SourceIssuer, e.UserID, dst.ID, s.targetIssuer(dst, e.TargetTenant), e.TargetSubject,
					nilIfEmpty(e.TargetTenant), dst.MappingRevision)
				if err != nil {
					return err
				}
				moved += int(tag.RowsAffected())
			}
			if _, err := tx.Exec(ctx, `UPDATE federation_transfer_entries SET outcome='applied', detail=$3 WHERE transfer_id=$1 AND seq=$2`,
				id, e.Seq, e.Outcome); err != nil {
				return err
			}
		}
		summary, err := s.analyzeTx(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE federation_transfers SET state='applied', applied_by_id=$2, applied_at=$3, version=version+1 WHERE id=$1`,
			id, actor.ID, now); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.transfer.applied", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "federation_transfer", ID: id}, Category: "security",
			Metadata: map[string]any{"moved": moved, "dropped_source_links": dropped, "summary": summary}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Transfer(ctx, realmID, id)
}

// CancelTransfer abandons a plan that was not applied.
func (s *Service) CancelTransfer(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE federation_transfers SET state='cancelled', version=version+1 WHERE realm_id=$1 AND id=$2 AND state IN ('draft','approved')`,
			realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			if _, err := s.Transfer(ctx, realmID, id); err != nil {
				return err
			}
			return problem.ErrConflict.WithDetail("an applied or cancelled transfer cannot be cancelled")
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.transfer.cancelled", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "federation_transfer", ID: id}, Category: "security"})
		return err
	})
}
