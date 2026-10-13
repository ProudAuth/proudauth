package realm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// ---------- evaluation ----------

// FlowFacts supplies the signals authentication flow rules test. Sign-in
// gathers them lazily from the transaction; simulation supplies them from a
// test case. EvaluateFlow asks for a signal only when a rule needs it, in a
// fixed order with the risk hook last, so both paths share one semantics.
type FlowFacts interface {
	ClientID() string
	OrganizationID() string
	Method() string
	ResourceAudiences() []string
	// ClientAddr is false when the client address is unknown.
	ClientAddr() (netip.Addr, bool)
	KnownDevice() bool
	FailedAttempts() int
	Privileged() bool
	// AssuranceBelow reports whether the assurance reached so far ranks
	// below acr.
	AssuranceBelow(acr string) bool
	// RiskAtLeast reports whether the risk reaches level; known is false
	// when the signal is missing or only a lower bound below level.
	RiskAtLeast(level string) (match, known bool)
}

// FlowResult is the outcome of evaluating a flow against one set of facts.
type FlowResult struct {
	Outcome string   `json:"outcome"`
	Rule    string   `json:"rule,omitempty"`
	Missing []string `json:"missing_signals,omitempty"`
}

// EvaluateFlow applies the first matching rule (AUT-012). A rule with a
// missing signal applies when its outcome is restrictive (unless it says
// skip) and never when it would allow, so a missing signal never satisfies a
// stricter policy (AUT-014). Without a match the outcome is allow.
func EvaluateFlow(p AuthFlowPolicy, f FlowFacts) FlowResult {
	res := FlowResult{Outcome: FlowAllow}
	var missing []string
	for _, r := range p.Rules {
		ok, miss := MatchFlowRule(r, f)
		if !ok {
			continue
		}
		if len(miss) > 0 {
			missing = append(missing, miss...)
			if skipsOnMissing(r) {
				continue
			}
		}
		res.Outcome, res.Rule = r.Outcome, r.Name
		break
	}
	slices.Sort(missing)
	res.Missing = slices.Compact(missing)
	return res
}

// MatchFlowRule evaluates one rule: every available condition must hold;
// conditions whose signal is unavailable are returned as missing.
func MatchFlowRule(r AuthFlowRule, f FlowFacts) (bool, []string) {
	w := r.When
	var missing []string
	if len(w.Clients) > 0 && !slices.Contains(w.Clients, f.ClientID()) {
		return false, nil
	}
	if len(w.Organizations) > 0 && (f.OrganizationID() == "" || !slices.Contains(w.Organizations, f.OrganizationID())) {
		return false, nil
	}
	if len(w.Methods) > 0 && !slices.Contains(w.Methods, f.Method()) {
		return false, nil
	}
	if len(w.Resources) > 0 && !slices.ContainsFunc(f.ResourceAudiences(), func(a string) bool { return slices.Contains(w.Resources, a) }) {
		return false, nil
	}
	if len(w.Networks) > 0 || len(w.OutsideNetworks) > 0 {
		ip, ok := f.ClientAddr()
		if !ok {
			missing = append(missing, "network")
		} else {
			ip = ip.Unmap()
			in := func(list []string) bool {
				return slices.ContainsFunc(list, func(c string) bool {
					p, err := netip.ParsePrefix(c)
					return err == nil && p.Contains(ip)
				})
			}
			if len(w.Networks) > 0 && !in(w.Networks) || len(w.OutsideNetworks) > 0 && in(w.OutsideNetworks) {
				return false, nil
			}
		}
	}
	if w.NewDevice != nil && *w.NewDevice == f.KnownDevice() {
		return false, nil
	}
	if w.FailedAttemptsAtLeast > 0 && f.FailedAttempts() < w.FailedAttemptsAtLeast {
		return false, nil
	}
	if w.Privileged != nil && *w.Privileged != f.Privileged() {
		return false, nil
	}
	if w.AssuranceBelow != "" && !f.AssuranceBelow(w.AssuranceBelow) {
		return false, nil
	}
	if w.RiskAtLeast != "" {
		match, known := f.RiskAtLeast(w.RiskAtLeast)
		if !known {
			missing = append(missing, "risk")
		} else if !match {
			return false, nil
		}
	}
	return true, missing
}

// skipsOnMissing reports whether a rule is passed over when one of its
// signals is missing.
func skipsOnMissing(r AuthFlowRule) bool {
	return r.Outcome == FlowAllow || r.OnMissingSignal == "skip"
}

// ---------- analysis ----------

// flowStrength orders outcomes from least to most restrictive.
var flowStrength = map[string]int{FlowAllow: 0, FlowReview: 1, FlowChallenge: 2, FlowRequireMFA: 3, FlowRequirePhishingResistant: 4, FlowDeny: 5}

// FlowStrength ranks an outcome: higher is more restrictive.
func FlowStrength(outcome string) int { return flowStrength[outcome] }

// FlowFinding is one result of analysing a flow definition.
type FlowFinding struct {
	Severity string `json:"severity"` // error or warning
	Code     string `json:"code"`
	Rule     string `json:"rule"`
	Index    int    `json:"index"`
	By       string `json:"by,omitempty"` // the earlier rule responsible
	Message  string `json:"message"`
}

// FlowAnalysis reports reachability and bypass paths in a flow (AUT-019).
// Errors block publishing; warnings must be acknowledged.
type FlowAnalysis struct {
	Errors      []FlowFinding `json:"errors"`
	Warnings    []FlowFinding `json:"warnings"`
	Unreachable []string      `json:"unreachable_rules"`
}

// Problem returns the first error as a validation problem, or nil.
func (a FlowAnalysis) Problem() error {
	if len(a.Errors) == 0 {
		return nil
	}
	e := a.Errors[0]
	return problem.ErrValidation.WithField(fmt.Sprintf("authentication_flow.rules[%d]", e.Index), e.Message)
}

// AnalyzeFlow finds rules no sign-in can reach and earlier, weaker rules
// that decide sign-ins a later, stricter rule was written for. A rule is
// unreachable when one earlier rule matches every sign-in it matches,
// including sign-ins with missing signals; when that earlier rule is weaker
// the stricter policy is bypassed outright, which is an error. Partial
// overlap with a weaker earlier rule, restrictive rules skipped on a missing
// signal and unconditional deny rules are warnings. Coverage is checked rule
// by rule; a stricter rule shadowed only by several earlier rules together
// is reported as partial overlap.
func AnalyzeFlow(p AuthFlowPolicy) FlowAnalysis {
	a := FlowAnalysis{Errors: []FlowFinding{}, Warnings: []FlowFinding{}, Unreachable: []string{}}
	for j, rj := range p.Rules {
		shadowed := false
		for i := 0; i < j; i++ {
			ri := p.Rules[i]
			if !ruleCovers(ri, rj) {
				continue
			}
			shadowed = true
			a.Unreachable = append(a.Unreachable, rj.Name)
			if flowStrength[ri.Outcome] < flowStrength[rj.Outcome] {
				a.Errors = append(a.Errors, FlowFinding{Severity: "error", Code: "bypass", Rule: rj.Name, Index: j, By: ri.Name,
					Message: fmt.Sprintf("rule %q (%s) is never reached: earlier rule %q (%s) matches every sign-in it matches", rj.Name, rj.Outcome, ri.Name, ri.Outcome)})
			} else {
				a.Warnings = append(a.Warnings, FlowFinding{Severity: "warning", Code: "unreachable", Rule: rj.Name, Index: j, By: ri.Name,
					Message: fmt.Sprintf("rule %q is never reached: earlier rule %q matches every sign-in it matches", rj.Name, ri.Name)})
			}
			break
		}
		if shadowed {
			continue
		}
		for i := 0; i < j; i++ {
			ri := p.Rules[i]
			if flowStrength[ri.Outcome] >= flowStrength[rj.Outcome] || !conditionsMayOverlap(ri.When, rj.When) {
				continue
			}
			msg := fmt.Sprintf("earlier rule %q (%s) decides some sign-ins rule %q (%s) also matches", ri.Name, ri.Outcome, rj.Name, rj.Outcome)
			if conditionCovers(ri.When, rj.When) {
				msg = fmt.Sprintf("earlier rule %q (%s) decides every sign-in rule %q (%s) matches whenever all signals are available", ri.Name, ri.Outcome, rj.Name, rj.Outcome)
			}
			a.Warnings = append(a.Warnings, FlowFinding{Severity: "warning", Code: "partial_bypass", Rule: rj.Name, Index: j, By: ri.Name, Message: msg})
		}
		if rj.Outcome != FlowAllow && rj.OnMissingSignal == "skip" && (hasNetwork(rj.When) || rj.When.RiskAtLeast != "") {
			a.Warnings = append(a.Warnings, FlowFinding{Severity: "warning", Code: "skip_on_missing", Rule: rj.Name, Index: j,
				Message: fmt.Sprintf("rule %q (%s) is skipped for sign-ins whose network or risk signal is unavailable", rj.Name, rj.Outcome)})
		}
		if rj.Outcome == FlowDeny && conditionEmpty(rj.When) {
			a.Warnings = append(a.Warnings, FlowFinding{Severity: "warning", Code: "deny_all", Rule: rj.Name, Index: j,
				Message: fmt.Sprintf("rule %q denies every sign-in that reaches it, administrators included", rj.Name)})
		}
	}
	return a
}

func hasNetwork(c AuthFlowCondition) bool { return len(c.Networks) > 0 || len(c.OutsideNetworks) > 0 }

func conditionEmpty(c AuthFlowCondition) bool {
	return len(c.Clients) == 0 && len(c.Organizations) == 0 && len(c.Methods) == 0 && len(c.Resources) == 0 && !hasNetwork(c) &&
		c.NewDevice == nil && c.FailedAttemptsAtLeast == 0 && c.RiskAtLeast == "" && c.Privileged == nil && c.AssuranceBelow == ""
}

// ruleCovers reports whether earlier rule a matches every sign-in rule b
// matches, including sign-ins with a missing signal: an earlier rule that is
// skipped on a missing signal covers b only if b is skipped too.
func ruleCovers(a, b AuthFlowRule) bool {
	if !conditionCovers(a.When, b.When) {
		return false
	}
	if skipsOnMissing(a) {
		if hasNetwork(a.When) && !(hasNetwork(b.When) && skipsOnMissing(b)) {
			return false
		}
		if a.When.RiskAtLeast != "" && !(b.When.RiskAtLeast != "" && skipsOnMissing(b)) {
			return false
		}
	}
	return true
}

// conditionCovers reports whether a holds whenever b holds, with every
// signal available. It is conservative: false when containment is unclear.
func conditionCovers(a, b AuthFlowCondition) bool {
	subset := func(outer, inner []string) bool {
		return len(outer) == 0 || len(inner) > 0 && !slices.ContainsFunc(inner, func(v string) bool { return !slices.Contains(outer, v) })
	}
	if !subset(a.Clients, b.Clients) || !subset(a.Organizations, b.Organizations) || !subset(a.Methods, b.Methods) || !subset(a.Resources, b.Resources) {
		return false
	}
	if len(a.Networks) > 0 && (len(b.Networks) == 0 || slices.ContainsFunc(prefixes(b.Networks), func(p netip.Prefix) bool { return !insideAny(p, prefixes(a.Networks)) })) {
		return false
	}
	// a excludes its outside networks; b must exclude them too, either
	// explicitly or by matching only networks disjoint from them.
	for _, x := range prefixes(a.OutsideNetworks) {
		if insideAny(x, prefixes(b.OutsideNetworks)) {
			continue
		}
		if len(b.Networks) > 0 && !slices.ContainsFunc(prefixes(b.Networks), func(n netip.Prefix) bool { return n.Overlaps(x) }) {
			continue
		}
		return false
	}
	if a.NewDevice != nil && (b.NewDevice == nil || *a.NewDevice != *b.NewDevice) {
		return false
	}
	if a.Privileged != nil && (b.Privileged == nil || *a.Privileged != *b.Privileged) {
		return false
	}
	if a.FailedAttemptsAtLeast > b.FailedAttemptsAtLeast {
		return false
	}
	if a.AssuranceBelow != "" && (b.AssuranceBelow == "" || slices.Index(FlowAssurances, b.AssuranceBelow) > slices.Index(FlowAssurances, a.AssuranceBelow)) {
		return false
	}
	if a.RiskAtLeast != "" && (b.RiskAtLeast == "" || slices.Index(RiskLevels, a.RiskAtLeast) > slices.Index(RiskLevels, b.RiskAtLeast)) {
		return false
	}
	return true
}

// conditionsMayOverlap is false only when no sign-in can satisfy both.
func conditionsMayOverlap(a, b AuthFlowCondition) bool {
	disjoint := func(x, y []string) bool {
		return len(x) > 0 && len(y) > 0 && !slices.ContainsFunc(x, func(v string) bool { return slices.Contains(y, v) })
	}
	if disjoint(a.Clients, b.Clients) || disjoint(a.Organizations, b.Organizations) || disjoint(a.Methods, b.Methods) {
		return false
	}
	if a.NewDevice != nil && b.NewDevice != nil && *a.NewDevice != *b.NewDevice {
		return false
	}
	if a.Privileged != nil && b.Privileged != nil && *a.Privileged != *b.Privileged {
		return false
	}
	an, bn := prefixes(a.Networks), prefixes(b.Networks)
	if len(an) > 0 && len(bn) > 0 && !slices.ContainsFunc(an, func(p netip.Prefix) bool {
		return slices.ContainsFunc(bn, func(q netip.Prefix) bool { return p.Overlaps(q) })
	}) {
		return false
	}
	excluded := func(nets []netip.Prefix, outside []string) bool {
		return len(nets) > 0 && !slices.ContainsFunc(nets, func(p netip.Prefix) bool { return !insideAny(p, prefixes(outside)) })
	}
	return !excluded(an, b.OutsideNetworks) && !excluded(bn, a.OutsideNetworks)
}

func prefixes(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, c := range list {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// insideAny reports whether p lies entirely within one of the prefixes.
func insideAny(p netip.Prefix, in []netip.Prefix) bool {
	return slices.ContainsFunc(in, func(q netip.Prefix) bool { return q.Bits() <= p.Bits() && q.Contains(p.Addr()) })
}

// FlowHash identifies a flow definition.
func FlowHash(p AuthFlowPolicy) string {
	doc, _ := json.Marshal(p)
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:])
}

// ---------- revisions ----------

// FlowRevision is one saved authentication-flow definition (AUT-019).
type FlowRevision struct {
	Revision       int            `json:"revision"`
	State          string         `json:"state"`
	Definition     AuthFlowPolicy `json:"definition"`
	DefinitionHash string         `json:"definition_hash"`
	BaseHash       string         `json:"base_hash"`
	Note           string         `json:"note,omitempty"`
	Analysis       FlowAnalysis   `json:"analysis"`
	RollbackOf     *int           `json:"rollback_of,omitempty"`
	PolicyRevision *int64         `json:"policy_revision,omitempty"`
	CreatedBy      audit.Ref      `json:"created_by"`
	CreatedAt      time.Time      `json:"created_at"`
	PublishedBy    *audit.Ref     `json:"published_by,omitempty"`
	PublishedAt    *time.Time     `json:"published_at,omitempty"`
}

const maxFlowDrafts = 20

const selectFlowRevision = `SELECT revision, state, definition, definition_hash, base_hash, note, analysis, rollback_of, policy_revision,
	created_by_type, created_by_id, created_at, published_by_type, published_by_id, published_at FROM auth_flow_revisions`

func scanFlowRevision(row pgx.Row) (*FlowRevision, error) {
	var fr FlowRevision
	var def, analysis []byte
	var pubType, pubID *string
	if err := row.Scan(&fr.Revision, &fr.State, &def, &fr.DefinitionHash, &fr.BaseHash, &fr.Note, &analysis, &fr.RollbackOf, &fr.PolicyRevision,
		&fr.CreatedBy.Type, &fr.CreatedBy.ID, &fr.CreatedAt, &pubType, &pubID, &fr.PublishedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(def, &fr.Definition)
	_ = json.Unmarshal(analysis, &fr.Analysis)
	if pubType != nil && pubID != nil {
		fr.PublishedBy = &audit.Ref{Type: *pubType, ID: *pubID}
	}
	return &fr, nil
}

// FlowRevisions lists a realm's flow revisions, newest first.
func (s *Service) FlowRevisions(ctx context.Context, realmID string) ([]FlowRevision, error) {
	rows, err := s.d.DB.Pool.Query(ctx, selectFlowRevision+` WHERE realm_id=$1 ORDER BY revision DESC LIMIT 200`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FlowRevision{}
	for rows.Next() {
		fr, err := scanFlowRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *fr)
	}
	return out, rows.Err()
}

// FlowRevision returns one revision.
func (s *Service) FlowRevision(ctx context.Context, realmID string, revision int) (*FlowRevision, error) {
	return scanFlowRevision(s.d.DB.Pool.QueryRow(ctx, selectFlowRevision+` WHERE realm_id=$1 AND revision=$2`, realmID, revision))
}

// validateFlowDefinition checks a definition the way a policy update would.
func (s *Service) validateFlowDefinition(def AuthFlowPolicy) error {
	if err := validateAuthFlow(def); err != nil {
		return err
	}
	return CheckChallengeProvider(Policy{AuthFlow: def}, s.d.Cfg)
}

// lockRealmTx locks the realm row, serializing revision numbering and
// publication with policy updates.
func lockRealmTx(ctx context.Context, tx pgx.Tx, realmID string) (*Realm, error) {
	return scanRealm(tx.QueryRow(ctx, selectRealm+` WHERE id=$1 FOR UPDATE`, realmID))
}

func insertFlowRevisionTx(ctx context.Context, tx pgx.Tx, realmID string, def AuthFlowPolicy, baseHash, state, note string, rollbackOf *int,
	actor audit.Ref, now time.Time) (int, error) {
	var next int
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(revision), 0) + 1 FROM auth_flow_revisions WHERE realm_id=$1`, realmID).Scan(&next); err != nil {
		return 0, err
	}
	doc, _ := json.Marshal(def)
	analysis, _ := json.Marshal(AnalyzeFlow(def))
	_, err := tx.Exec(ctx, `INSERT INTO auth_flow_revisions (realm_id, revision, definition, definition_hash, base_hash, state, note, analysis,
		rollback_of, created_by_type, created_by_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		realmID, next, doc, FlowHash(def), baseHash, state, note, analysis, rollbackOf, actor.Type, actor.ID, now)
	return next, err
}

// CreateFlowDraft saves a draft revision with its analysis. The draft
// remembers the live flow it was based on.
func (s *Service) CreateFlowDraft(ctx context.Context, realmID string, def AuthFlowPolicy, note string, actor audit.Ref) (*FlowRevision, error) {
	if err := s.validateFlowDefinition(def); err != nil {
		return nil, err
	}
	if len(note) > 500 {
		return nil, problem.ErrValidation.WithField("note", "at most 500 characters")
	}
	var rev int
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := lockRealmTx(ctx, tx, realmID)
		if err != nil {
			return err
		}
		var drafts int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM auth_flow_revisions WHERE realm_id=$1 AND state='draft'`, realmID).Scan(&drafts); err != nil {
			return err
		}
		if drafts >= maxFlowDrafts {
			return problem.ErrConflict.WithDetail(fmt.Sprintf("at most %d open drafts; publish or discard one first", maxFlowDrafts))
		}
		rev, err = insertFlowRevisionTx(ctx, tx, realmID, def, FlowHash(cur.Policy.AuthFlow), "draft", note, nil, actor, s.d.Now())
		if err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.auth_flow.draft_created", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "auth_flow_revision", ID: fmt.Sprint(rev)}, Category: "security",
			Metadata: map[string]any{"revision": rev, "rules": len(def.Rules), "definition_hash": FlowHash(def)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.FlowRevision(ctx, realmID, rev)
}

// DiscardFlowDraft discards a draft.
func (s *Service) DiscardFlowDraft(ctx context.Context, realmID string, revision int, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE auth_flow_revisions SET state='discarded' WHERE realm_id=$1 AND revision=$2 AND state='draft'`, realmID, revision)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			if _, err := scanFlowRevision(tx.QueryRow(ctx, selectFlowRevision+` WHERE realm_id=$1 AND revision=$2`, realmID, revision)); err != nil {
				return err
			}
			return problem.ErrConflict.WithDetail("only a draft can be discarded")
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.auth_flow.draft_discarded", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "auth_flow_revision", ID: fmt.Sprint(revision)}, Category: "security", Metadata: map[string]any{"revision": revision}})
		return err
	})
}

// PublishFlowRevision makes a draft the live flow. It refuses a draft whose
// base no longer matches the live flow (someone published or edited since),
// a definition with bypass errors, and warnings that were not acknowledged.
// Publishing goes through UpdatePolicyTx, so the policy revision advances
// and the change is in the configuration history.
func (s *Service) PublishFlowRevision(ctx context.Context, realmID string, revision int, acknowledge bool, actor audit.Ref, reason string) (*FlowRevision, *Realm, error) {
	var out *Realm
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := lockRealmTx(ctx, tx, realmID)
		if err != nil {
			return err
		}
		fr, err := scanFlowRevision(tx.QueryRow(ctx, selectFlowRevision+` WHERE realm_id=$1 AND revision=$2 FOR UPDATE`, realmID, revision))
		if err != nil {
			return err
		}
		if fr.State != "draft" {
			return problem.ErrConflict.WithDetail("only a draft can be published; roll back to republish an earlier revision")
		}
		if fr.BaseHash != FlowHash(cur.Policy.AuthFlow) {
			return problem.ErrConflict.WithDetail("the live authentication flow changed after this draft was created; create a new draft from the current flow")
		}
		out, err = s.publishFlowTx(ctx, tx, cur, fr, acknowledge, actor, reason)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	s.Invalidate(out.Name)
	fr, err := s.FlowRevision(ctx, realmID, revision)
	return fr, out, err
}

// RollbackFlow publishes a copy of an earlier published revision as a new
// revision. Analysis runs again: a revision that is now found to contain a
// bypass cannot be restored.
func (s *Service) RollbackFlow(ctx context.Context, realmID string, to int, acknowledge bool, actor audit.Ref, reason string) (*FlowRevision, *Realm, error) {
	var out *Realm
	var rev int
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := lockRealmTx(ctx, tx, realmID)
		if err != nil {
			return err
		}
		old, err := scanFlowRevision(tx.QueryRow(ctx, selectFlowRevision+` WHERE realm_id=$1 AND revision=$2`, realmID, to))
		if err != nil {
			return err
		}
		if old.State != "published" && old.State != "superseded" {
			return problem.ErrConflict.WithDetail("only a revision that was published can be restored")
		}
		if err := s.validateFlowDefinition(old.Definition); err != nil {
			return err
		}
		note := fmt.Sprintf("rollback to revision %d", to)
		if rev, err = insertFlowRevisionTx(ctx, tx, realmID, old.Definition, FlowHash(cur.Policy.AuthFlow), "draft", note, &to, actor, s.d.Now()); err != nil {
			return err
		}
		fr, err := scanFlowRevision(tx.QueryRow(ctx, selectFlowRevision+` WHERE realm_id=$1 AND revision=$2`, realmID, rev))
		if err != nil {
			return err
		}
		if reason == "" {
			reason = note
		}
		out, err = s.publishFlowTx(ctx, tx, cur, fr, acknowledge, actor, reason)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	s.Invalidate(out.Name)
	fr, err := s.FlowRevision(ctx, realmID, rev)
	return fr, out, err
}

func (s *Service) publishFlowTx(ctx context.Context, tx pgx.Tx, cur *Realm, fr *FlowRevision, acknowledge bool, actor audit.Ref, reason string) (*Realm, error) {
	analysis := AnalyzeFlow(fr.Definition)
	if err := analysis.Problem(); err != nil {
		return nil, err
	}
	if len(analysis.Warnings) > 0 && !acknowledge {
		return nil, problem.ErrValidation.WithField("acknowledge_warnings", fmt.Sprintf("the definition has %d warning(s); review the analysis and set acknowledge_warnings", len(analysis.Warnings)))
	}
	p := cur.Policy
	p.AuthFlow = fr.Definition
	return s.UpdatePolicyTx(context.WithValue(ctx, publishingFlowKey{}, fr.Revision), tx, cur.ID, 0, p, actor, reason)
}

type publishingFlowKey struct{}

// recordFlowChangeTx keeps the revision history in step with the live flow.
// A flow changed through the settings document or a configuration import
// becomes a new published revision; a published draft is marked published.
// Either way a bypass error refuses the change.
func (s *Service) recordFlowChangeTx(ctx context.Context, tx pgx.Tx, cur *Realm, next AuthFlowPolicy, policyRevision int64, actor audit.Ref, reason string, now time.Time) error {
	publishing, _ := ctx.Value(publishingFlowKey{}).(int)
	if publishing == 0 && FlowHash(cur.Policy.AuthFlow) == FlowHash(next) {
		return nil
	}
	if err := AnalyzeFlow(next).Problem(); err != nil {
		return err
	}
	rev := publishing
	if rev == 0 {
		var err error
		if rev, err = insertFlowRevisionTx(ctx, tx, cur.ID, next, FlowHash(cur.Policy.AuthFlow), "draft", reason, nil, actor, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE auth_flow_revisions SET state='superseded' WHERE realm_id=$1 AND state='published'`, cur.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth_flow_revisions SET state='published', policy_revision=$3, published_by_type=$4, published_by_id=$5,
		published_at=$6 WHERE realm_id=$1 AND revision=$2`, cur.ID, rev, policyRevision, actor.Type, actor.ID, now); err != nil {
		return err
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "realm.auth_flow.published", RealmID: cur.ID, Actor: actor,
		Target: &audit.Ref{Type: "auth_flow_revision", ID: fmt.Sprint(rev)}, ReasonCode: reason, Category: "security",
		Metadata: map[string]any{"revision": rev, "policy_revision": policyRevision, "rules": len(next.Rules), "definition_hash": FlowHash(next)}})
	return err
}
