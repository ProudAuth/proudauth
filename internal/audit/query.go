package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/storage"
)

// Filter selects audit events. RealmID is mandatory and OrgID, when set by the
// caller's authorization scope, is enforced as a hard boundary (AUD-006).
type Filter struct {
	RealmID              string
	OrgID                string
	EventID              string
	ActorID              string
	SubjectID            string
	Type                 string
	TypePrefix           string
	Outcome              string
	ClientID             string
	RequestID            string
	GrantID              string
	ImpersonationGrantID string
	SessionID            string
	TargetID             string
	Category             string
	// Network is a CIDR prefix; events whose stored, already truncated network
	// context overlaps it match (AUD-011). Full addresses are never reconstructed.
	Network   string
	From, To  *time.Time
	BeforeSeq int64
	Limit     int
}

// Query returns events newest first with a sequence cursor.
func Query(ctx context.Context, q storage.Querier, f Filter) ([]Event, int64, error) {
	if f.RealmID == "" {
		return nil, 0, fmt.Errorf("audit: realm scope required")
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	conds := []string{"realm_id = $1"}
	args := []any{f.RealmID}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if f.OrgID != "" {
		add("organization_id = ?", f.OrgID)
	}
	if f.EventID != "" {
		add("id = ?", f.EventID)
	}
	// Identifiers are stored bounded (BoundID): a filter on the original
	// value finds them.
	if f.ActorID != "" {
		add("actor_id = ?", BoundID(f.ActorID))
	}
	if f.SubjectID != "" {
		add("subject_id = ?", BoundID(f.SubjectID))
	}
	if f.Type != "" {
		add("type = ?", f.Type)
	}
	if f.TypePrefix != "" {
		// AUD-011 specifies a literal prefix. Event names may contain an
		// underscore; neither it nor caller-supplied percent/backslash is a
		// LIKE wildcard or escape instruction.
		prefix := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(f.TypePrefix)
		add(`type LIKE ? || '%' ESCAPE '\'`, prefix)
	}
	if f.Outcome != "" {
		add("outcome = ?", f.Outcome)
	}
	if f.ClientID != "" {
		add("client_id = ?", f.ClientID)
	}
	if f.RequestID != "" {
		add("request_id = ?", f.RequestID)
	}
	if f.GrantID != "" {
		add("grant_id = ?", f.GrantID)
	}
	if f.ImpersonationGrantID != "" {
		// The grant's evidence includes the request it was issued from:
		// request and approval events precede the grant (IMP-024).
		add(`(impersonation_grant_id = ? OR (target_type = 'impersonation_request'
			AND target_id = (SELECT request_id FROM impersonation_grants WHERE id = ?)))`, f.ImpersonationGrantID)
	}
	if f.SessionID != "" {
		add("(session_id = ? OR actor_session_id = ?)", f.SessionID)
	}
	if f.TargetID != "" {
		add("target_id = ?", BoundID(f.TargetID))
	}
	if f.Category != "" {
		add("category = ?", f.Category)
	}
	if f.Network != "" {
		add(`CASE WHEN ip_context ~ '^[0-9a-fA-F:.]+(/[0-9]{1,3}){0,1}$' THEN ip_context::inet && ?::inet ELSE false END`, f.Network)
	}
	if f.From != nil {
		add("occurred_at >= ?", *f.From)
	}
	if f.To != nil {
		add("occurred_at < ?", *f.To)
	}
	if f.BeforeSeq > 0 {
		add("seq < ?", f.BeforeSeq)
	}
	args = append(args, f.Limit)
	sql := `SELECT seq, id, schema_version, type, occurred_at, coalesce(realm_id,''), coalesce(organization_id,''), actor_type, actor_id,
		coalesce(actor_session_id,''), coalesce(subject_type,''), coalesce(subject_id,''), coalesce(target_type,''), coalesce(target_id,''), outcome,
		coalesce(reason_code,''), coalesce(request_id,''), coalesce(client_id,''), coalesce(session_id,''), coalesce(grant_id,''),
		coalesce(impersonation_grant_id,''), source, coalesce(reporting_service,''), coalesce(ip_context,''), metadata, category, content_hash,
		coalesce(batch_id,'') FROM audit_events WHERE ` + strings.Join(conds, " AND ") + fmt.Sprintf(` ORDER BY seq DESC LIMIT $%d`, len(args))
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Event
	var last int64
	for rows.Next() {
		ev, seq, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
		last = seq
	}
	if len(out) < f.Limit {
		last = 0
	}
	return out, last, rows.Err()
}

func scanEvent(rows pgx.Rows) (Event, int64, error) {
	var ev Event
	var seq int64
	var meta []byte
	var subjType, subjID, tgtType, tgtID string
	err := rows.Scan(&seq, &ev.ID, &ev.SchemaVersion, &ev.Type, &ev.OccurredAt, &ev.RealmID, &ev.OrgID, &ev.Actor.Type, &ev.Actor.ID,
		&ev.Actor.SessionID, &subjType, &subjID, &tgtType, &tgtID, &ev.Outcome, &ev.ReasonCode, &ev.RequestID, &ev.ClientID, &ev.SessionID,
		&ev.GrantID, &ev.ImpersonationGrantID, &ev.Source, &ev.ReportingService, &ev.IPContext, &meta, &ev.Category, &ev.ContentHash, &ev.BatchID)
	if err != nil {
		return ev, 0, err
	}
	if subjID != "" {
		ev.Subject = &Ref{Type: subjType, ID: subjID}
	}
	if tgtID != "" {
		ev.Target = &Ref{Type: tgtType, ID: tgtID}
	}
	_ = json.Unmarshal(meta, &ev.Metadata)
	ev.OccurredAt = ev.OccurredAt.UTC()
	return ev, seq, nil
}

// ---------- tamper evidence ----------

// SealBatch assigns unsealed events to a new hash-linked batch (AUD-008). Each
// batch commits the digest of its members' content hashes and the previous batch
// hash. A batch signer may additionally sign batch_hash.
func SealBatch(ctx context.Context, db *storage.DB, max int, sign func(hash string) (sig, kid string, err error)) (int, error) {
	sealed := 0
	err := db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(727274002)`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT seq, id, content_hash FROM audit_events WHERE batch_id IS NULL AND recorded_at < now() - interval '2 seconds'
			ORDER BY seq LIMIT $1`, max)
		if err != nil {
			return err
		}
		type item struct {
			seq      int64
			id, hash string
		}
		var items []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.seq, &it.id, &it.hash); err != nil {
				rows.Close()
				return err
			}
			items = append(items, it)
		}
		rows.Close()
		if len(items) == 0 {
			return nil
		}
		var prevHash string
		var prevSeq int64
		err = tx.QueryRow(ctx, `SELECT batch_hash, sequence_number FROM audit_batches ORDER BY sequence_number DESC LIMIT 1`).Scan(&prevHash, &prevSeq)
		if storage.IsNoRows(err) {
			prevHash, prevSeq = strings.Repeat("0", 64), 0
		} else if err != nil {
			return err
		}
		h := sha256.New()
		ids2 := make([]string, 0, len(items))
		for _, it := range items {
			h.Write([]byte(it.id + ":" + it.hash + "\n"))
			ids2 = append(ids2, it.id)
		}
		eventsDigest := hex.EncodeToString(h.Sum(nil))
		bh := sha256.Sum256([]byte(prevHash + "|" + eventsDigest + "|" + fmt.Sprint(prevSeq+1)))
		batchHash := hex.EncodeToString(bh[:])
		var sig, kid *string
		if sign != nil {
			s, k, err := sign(batchHash)
			if err == nil {
				sig, kid = &s, &k
			}
		}
		batchID := ids.New(ids.AuditBatch)
		if _, err := tx.Exec(ctx, `INSERT INTO audit_batches (id, sequence_number, previous_hash, events_digest, batch_hash, event_count, first_seq, last_seq, signature, signing_kid)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, batchID, prevSeq+1, prevHash, eventsDigest, batchHash, len(items), items[0].seq,
			items[len(items)-1].seq, sig, kid); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE audit_events SET batch_id=$1 WHERE id = ANY($2)`, batchID, ids2); err != nil {
			return err
		}
		sealed = len(items)
		return nil
	})
	return sealed, err
}

// VerificationReport is the result of verifying the audit chain.
type VerificationReport struct {
	Signed   int      `json:"batches_signature_verified"`
	Pruned   int      `json:"batches_pruned_by_retention"`
	Batches  int      `json:"batches_checked"`
	Events   int      `json:"events_checked"`
	Unsealed int      `json:"unsealed_events"`
	Problems []string `json:"problems"`
	OK       bool     `json:"ok"`
	// Archive verification only: the range of the main archive and any fork
	// directories written after a database restore.
	FirstSequence int64    `json:"first_sequence,omitempty"`
	LastSequence  int64    `json:"last_sequence,omitempty"`
	Forks         []string `json:"forks,omitempty"`
}

// VerifyChain recomputes event content hashes, batch digests and the hash chain.
// It detects edits made by anyone who bypassed the append-only guard, but cannot
// protect against an operator who rewrites the entire chain and every external
// anchor (§21 important limit).
func VerifyChain(ctx context.Context, q storage.Querier) (*VerificationReport, error) {
	return VerifyChainWith(ctx, q, nil)
}

// VerifyChainWith also verifies batch signatures when verify is non-nil; an
// unsigned or badly signed batch is then reported (AUD-008).
func VerifyChainWith(ctx context.Context, q storage.Querier, verify func(kid, hash, sig string) bool) (*VerificationReport, error) {
	return verifyFrom(ctx, q, 0, verify)
}

// VerifyRecent verifies the last n sealed batches, anchored on the stored hash
// of the batch before them (AUD-014 scheduled checks).
func VerifyRecent(ctx context.Context, q storage.Querier, n int, verify func(kid, hash, sig string) bool) (*VerificationReport, error) {
	var last int64
	if err := q.QueryRow(ctx, `SELECT coalesce(max(sequence_number),0) FROM audit_batches`).Scan(&last); err != nil {
		return nil, err
	}
	from := last - int64(n)
	if from < 0 {
		from = 0
	}
	return verifyFrom(ctx, q, from, verify)
}

func verifyFrom(ctx context.Context, q storage.Querier, from int64, verify func(kid, hash, sig string) bool) (*VerificationReport, error) {
	rep := &VerificationReport{Problems: []string{}}
	prev := strings.Repeat("0", 64)
	if from > 0 {
		if err := q.QueryRow(ctx, `SELECT batch_hash FROM audit_batches WHERE sequence_number=$1`, from).Scan(&prev); err != nil {
			return nil, err
		}
	}
	rows, err := q.Query(ctx, `SELECT b.id, b.sequence_number, b.previous_hash, b.events_digest, b.batch_hash, coalesce(b.signature,''), coalesce(b.signing_kid,''),
		p.batch_id IS NOT NULL FROM audit_batches b LEFT JOIN audit_prunes p ON p.batch_id=b.id WHERE b.sequence_number > $1 ORDER BY b.sequence_number`, from)
	if err != nil {
		return nil, err
	}
	type batch struct {
		id, prev, digest, hash, sig, kid string
		seq                              int64
		pruned                           bool
	}
	var batches []batch
	for rows.Next() {
		var b batch
		if err := rows.Scan(&b.id, &b.seq, &b.prev, &b.digest, &b.hash, &b.sig, &b.kid, &b.pruned); err != nil {
			rows.Close()
			return nil, err
		}
		batches = append(batches, b)
	}
	rows.Close()
	for i, b := range batches {
		rep.Batches++
		if b.seq != from+int64(i+1) {
			rep.Problems = append(rep.Problems, fmt.Sprintf("batch sequence gap at %d", b.seq))
		}
		if b.prev != prev {
			rep.Problems = append(rep.Problems, fmt.Sprintf("batch %s previous hash mismatch", b.id))
		}
		erows, err := q.Query(ctx, `SELECT seq, id, schema_version, type, occurred_at, coalesce(realm_id,''), coalesce(organization_id,''), actor_type, actor_id,
			coalesce(actor_session_id,''), coalesce(subject_type,''), coalesce(subject_id,''), coalesce(target_type,''), coalesce(target_id,''), outcome,
			coalesce(reason_code,''), coalesce(request_id,''), coalesce(client_id,''), coalesce(session_id,''), coalesce(grant_id,''),
			coalesce(impersonation_grant_id,''), source, coalesce(reporting_service,''), coalesce(ip_context,''), metadata, category, content_hash,
			coalesce(batch_id,'') FROM audit_events WHERE batch_id=$1 ORDER BY seq`, b.id)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		for erows.Next() {
			ev, _, err := scanEvent(erows)
			if err != nil {
				erows.Close()
				return nil, err
			}
			rep.Events++
			stored := ev.ContentHash
			if ContentHash(ev) != stored {
				rep.Problems = append(rep.Problems, fmt.Sprintf("event %s content hash mismatch", ev.ID))
			}
			h.Write([]byte(ev.ID + ":" + stored + "\n"))
		}
		erows.Close()
		// A pruned batch lost events to retention by design (recorded in the
		// append-only prune ledger): its digest cannot be recomputed, but its
		// retained events and its place in the hash chain are still verified.
		if !b.pruned && hex.EncodeToString(h.Sum(nil)) != b.digest {
			rep.Problems = append(rep.Problems, fmt.Sprintf("batch %s events digest mismatch", b.id))
		}
		bh := sha256.Sum256([]byte(b.prev + "|" + b.digest + "|" + fmt.Sprint(b.seq)))
		if hex.EncodeToString(bh[:]) != b.hash {
			rep.Problems = append(rep.Problems, fmt.Sprintf("batch %s hash mismatch", b.id))
		}
		if verify != nil {
			if !verify(b.kid, b.hash, b.sig) {
				rep.Problems = append(rep.Problems, fmt.Sprintf("batch %s signature missing or invalid", b.id))
			} else if b.sig != "" {
				rep.Signed++
			}
		}
		if b.pruned {
			rep.Pruned++
		}
		prev = b.hash
	}
	_ = q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE batch_id IS NULL`).Scan(&rep.Unsealed)
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

// Retention describes audit retention (AUD-009): a default cutoff, per
// category cutoffs, and categories that are never pruned. Events under an
// active legal hold are never pruned either.
type Retention struct {
	Default    time.Time
	Categories map[string]time.Time
	Keep       []string
	// ArchivedThrough, when positive, limits pruning to batches the audit
	// archive has already written, so archived files are always complete.
	ArchivedThrough int64
	// Archiving is set when an archive is configured; with ArchivedThrough 0
	// nothing has been archived yet and nothing is pruned.
	Archiving bool
	// Realms and Orgs hold scope cutoffs for realms and organizations that
	// keep evidence longer than the deployment's retention (AUD-009); an
	// event goes only when every applicable retention has passed.
	Realms map[string]time.Time
	Orgs   map[string]time.Time
}

func scopeArrays(m map[string]time.Time) ([]string, []time.Time) {
	ids := []string{}
	ts := []time.Time{}
	for k, v := range m {
		ids = append(ids, k)
		ts = append(ts, v)
	}
	return ids, ts
}

// PruneExpired removes sealed events whose category's retention has passed,
// in at most max batches per run. The first pass over a batch is recorded in
// audit_prunes (its digest can no longer be recomputed); later passes, when a
// longer-retained category expires, in audit_prune_log.
func PruneExpired(ctx context.Context, tx pgx.Tx, r Retention, max int) (int, error) {
	cats := []string{}
	cutoffs := []time.Time{}
	for c, t := range r.Categories {
		cats = append(cats, c)
		cutoffs = append(cutoffs, t)
	}
	for _, c := range r.Keep {
		cats = append(cats, c)
		cutoffs = append(cutoffs, time.Unix(0, 0).UTC())
	}
	realmIDs, realmCuts := scopeArrays(r.Realms)
	orgIDs, orgCuts := scopeArrays(r.Orgs)
	// scope joins the realm and organization cutoffs; p is the first of
	// their four parameter positions.
	scope := func(alias string, p int) string {
		return fmt.Sprintf(` LEFT JOIN unnest($%d::text[], $%d::timestamptz[]) AS rr(id, cutoff) ON rr.id = %s.realm_id
			LEFT JOIN unnest($%d::text[], $%d::timestamptz[]) AS oo(id, cutoff) ON oo.id = %s.organization_id`, p, p+1, alias, p+2, p+3, alias)
	}
	const expired = `e.batch_id IS NOT NULL
		AND e.occurred_at < LEAST(coalesce(rc.cutoff, $3), coalesce(rr.cutoff, 'infinity'::timestamptz), coalesce(oo.cutoff, 'infinity'::timestamptz))
		AND NOT EXISTS (SELECT 1 FROM audit_legal_holds h WHERE h.released_at IS NULL AND h.realm_id = e.realm_id
			AND (h.organization_id IS NULL OR h.organization_id = e.organization_id)
			AND (h.subject_id IS NULL OR h.subject_id = e.subject_id OR h.subject_id = e.actor_id))`
	rows, err := tx.Query(ctx, `SELECT DISTINCT e.batch_id FROM audit_events e
		LEFT JOIN unnest($1::text[], $2::timestamptz[]) AS rc(category, cutoff) ON rc.category = e.category`+scope("e", 7)+`
		WHERE `+expired+` AND (NOT $5 OR e.batch_id IN (SELECT b.id FROM audit_batches b WHERE b.sequence_number <= $6)) LIMIT $4`,
		cats, cutoffs, r.Default, max, r.Archiving, r.ArchivedThrough, realmIDs, realmCuts, orgIDs, orgCuts)
	if err != nil {
		return 0, err
	}
	var batches []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		batches = append(batches, id)
	}
	rows.Close()
	removed := 0
	for _, id := range batches {
		// The candidates by the deployment's retention policy; the owner-run
		// function re-checks holds, sealing and archiving, deletes and
		// records the prune itself (AUD-007).
		rows, err := tx.Query(ctx, `SELECT e2.id FROM audit_events e2
			LEFT JOIN unnest($1::text[], $2::timestamptz[]) AS rc(category, cutoff) ON rc.category = e2.category`+scope("e2", 5)+`
			WHERE e2.batch_id = $4 AND `+strings.ReplaceAll(expired, "e.", "e2."), cats, cutoffs, r.Default, id, realmIDs, realmCuts, orgIDs, orgCuts)
		if err != nil {
			return removed, err
		}
		var ids []string
		for rows.Next() {
			var eid string
			if err := rows.Scan(&eid); err != nil {
				rows.Close()
				return removed, err
			}
			ids = append(ids, eid)
		}
		rows.Close()
		if len(ids) == 0 {
			continue
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT proudauth_audit_prune($1, $2)`, id, ids).Scan(&n); err != nil {
			return removed, err
		}
		removed += n
	}
	return removed, nil
}
