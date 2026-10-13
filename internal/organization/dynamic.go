package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// DynamicRule derives a group's members from authoritative account attributes
// (TEN-014): every condition must hold. Only attributes users cannot edit
// themselves may be used, so nobody can join a group (and its roles) by
// changing their own profile.
type DynamicRule struct {
	All []DynamicCondition `json:"all"`
}

// DynamicCondition compares one profile attribute.
type DynamicCondition struct {
	Attribute string   `json:"attribute"`
	Equals    string   `json:"equals,omitempty"`
	In        []string `json:"in,omitempty"`
}

// RuleStatus reports a dynamic group's last recomputation.
type RuleStatus struct {
	Rule         *DynamicRule `json:"rule"`
	RecomputedAt *string      `json:"recomputed_at,omitempty"`
	MemberCount  *int         `json:"member_count,omitempty"`
	Error        string       `json:"error,omitempty"`
}

// validate checks the rule against the realm's attribute schema.
func (r DynamicRule) validate(schema []identity.AttributeDef) error {
	if len(r.All) == 0 || len(r.All) > 5 {
		return fmt.Errorf("1 to 5 conditions")
	}
	for _, c := range r.All {
		i := slices.IndexFunc(schema, func(a identity.AttributeDef) bool { return a.Name == c.Attribute })
		if i < 0 {
			return fmt.Errorf("unknown attribute %s", c.Attribute)
		}
		if schema[i].UserEditable {
			return fmt.Errorf("attribute %s is user-editable; dynamic membership needs an authoritative attribute", c.Attribute)
		}
		if (c.Equals == "") == (len(c.In) == 0) || len(c.In) > 20 {
			return fmt.Errorf("condition on %s needs exactly one of equals or in (at most 20 values)", c.Attribute)
		}
	}
	return nil
}

// SetDynamicRule makes a group dynamic (rule) or static again (nil) and
// recomputes its members at once. Manual members are replaced by the rule.
func (s *Service) SetDynamicRule(ctx context.Context, realmID, orgID, groupID string, rule *DynamicRule, schema []identity.AttributeDef,
	subject authorization.Subject, actor audit.Ref) (*RuleStatus, error) {
	if rule != nil {
		if err := rule.validate(schema); err != nil {
			return nil, problem.ErrValidation.WithField("rule", err.Error())
		}
	}
	var skipped map[string]bool
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.checkGroupCeilingTx(ctx, tx, realmID, orgID, groupID, subject); err != nil {
			return err
		}
		var raw []byte
		if rule != nil {
			raw, _ = json.Marshal(rule)
		}
		tag, err := tx.Exec(ctx, `UPDATE groups SET dynamic_rule=$3, source=CASE WHEN $3::jsonb IS NULL THEN 'admin' ELSE 'dynamic' END,
			rule_error=NULL, version=version+1, updated_at=$4 WHERE organization_id=$1 AND id=$2`, orgID, groupID, raw, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if rule == nil {
			// Removing the rule freezes its members as ordinary members: they
			// keep their access, and later changes are manual (TEN-014).
			tag, err := tx.Exec(ctx, `UPDATE group_memberships SET source='admin' WHERE group_id=$1 AND source='dynamic'`, groupID)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id IN (SELECT membership_id FROM group_memberships WHERE group_id=$1)`,
				groupID); err != nil {
				return err
			}
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.dynamic_rule.removed", RealmID: realmID, OrgID: orgID, Actor: actor,
				Category: "authorization", Target: &audit.Ref{Type: "group", ID: groupID}, Metadata: map[string]any{"members_kept": tag.RowsAffected()}}); err != nil {
				return err
			}
		}
		if rule != nil {
			// Members added by hand do not survive the switch to a rule; each
			// removal is audited.
			rows, err := tx.Query(ctx, `DELETE FROM group_memberships WHERE group_id=$1 AND source <> 'dynamic' RETURNING membership_id`, groupID)
			if err != nil {
				return err
			}
			var removed []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				removed = append(removed, id)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, id := range removed {
				if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, id); err != nil {
					return err
				}
				if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.member.removed", RealmID: realmID, OrgID: orgID, Actor: actor,
					Category: "authorization", Target: &audit.Ref{Type: "group", ID: groupID},
					Metadata: map[string]any{"membership_id": id, "source": "dynamic_rule_set"}}); err != nil {
					return err
				}
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "group.dynamic_rule.set", RealmID: realmID, OrgID: orgID, Actor: actor,
			Target: &audit.Ref{Type: "group", ID: groupID}, Metadata: map[string]any{"dynamic": rule != nil}}); err != nil {
			return err
		}
		// A new rule starts afresh: every member it leaves out is audited.
		skipped, err = s.recomputeTx(ctx, tx, realmID, orgID, groupID, rule, schema, actor, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.skips.set(groupID, skipped)
	return s.RuleStatusOf(ctx, orgID, groupID)
}

// dynamicSkips holds, per dynamic group, the memberships the previous
// recomputation left out for a separation-of-duties conflict (AZ-018). A
// skip is audited when it is new, not again on every recomputation while the
// conflict lasts. The memory is per process: after a restart a lasting skip
// is audited once more.
type dynamicSkips struct {
	mu sync.Mutex
	m  map[string]map[string]bool
}

func (d *dynamicSkips) get(groupID string) map[string]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[groupID]
}

// set records a committed recomputation's skips (nil forgets the group).
func (d *dynamicSkips) set(groupID string, skipped map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(skipped) == 0 {
		delete(d.m, groupID)
		return
	}
	if d.m == nil {
		d.m = map[string]map[string]bool{}
	}
	d.m[groupID] = skipped
}

// RuleStatusOf returns a group's rule and recomputation status.
func (s *Service) RuleStatusOf(ctx context.Context, orgID, groupID string) (*RuleStatus, error) {
	var raw []byte
	var at *string
	var count *int
	var errText *string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT dynamic_rule, to_char(rule_recomputed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		rule_member_count, rule_error FROM groups WHERE organization_id=$1 AND id=$2`, orgID, groupID).Scan(&raw, &at, &count, &errText)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	st := &RuleStatus{RecomputedAt: at, MemberCount: count}
	if errText != nil {
		st.Error = *errText
	}
	if raw != nil {
		var r DynamicRule
		if json.Unmarshal(raw, &r) == nil {
			st.Rule = &r
		}
	}
	return st, nil
}

// maxRuleMembers bounds the members one dynamic rule can derive.
const maxRuleMembers = 10000

// recomputeTx brings a dynamic group's members in line with its rule. A rule
// that no longer validates against the schema (for example because an
// attribute became user-editable) fails closed: every rule-derived member is
// removed and the error is recorded.
//
// Every member added or removed is audited like a manual change, with source
// "dynamic" and the actor that caused the recomputation (the administrator
// who set the rule, or the system for scheduled recomputation). A member
// left out for a separation-of-duties conflict is audited when the skip is
// new, that is, not among prevSkipped (the previous recomputation's skips);
// the skips of this recomputation are returned for the caller to remember
// once the transaction commits. rule_member_count counts actual members only.
func (s *Service) recomputeTx(ctx context.Context, tx pgx.Tx, realmID, orgID, groupID string, rule *DynamicRule, schema []identity.AttributeDef, actor audit.Ref,
	prevSkipped map[string]bool) (map[string]bool, error) {
	record := func(typ, membershipID string) error {
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: typ, RealmID: realmID, OrgID: orgID, Actor: actor, Category: "authorization",
			Target: &audit.Ref{Type: "group", ID: groupID}, Metadata: map[string]any{"membership_id": membershipID, "source": "dynamic"}})
		return err
	}
	if rule == nil {
		_, err := tx.Exec(ctx, `UPDATE groups SET rule_recomputed_at=NULL, rule_member_count=NULL, rule_error=NULL WHERE id=$1`, groupID)
		return nil, err
	}
	desired := map[string]bool{}
	ruleErr := ""
	if err := rule.validate(schema); err != nil {
		ruleErr = err.Error()
	} else {
		conds := ""
		args := []any{orgID}
		for _, c := range rule.All {
			args = append(args, c.Attribute)
			attr := fmt.Sprintf("$%d", len(args))
			if c.Equals != "" {
				args = append(args, c.Equals)
				conds += fmt.Sprintf(" AND u.profile->>%s = $%d", attr, len(args))
			} else {
				args = append(args, c.In)
				conds += fmt.Sprintf(" AND u.profile->>%s = ANY($%d)", attr, len(args))
			}
		}
		rows, err := tx.Query(ctx, `SELECT m.id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.state='active'
			AND u.state='active'`+conds+fmt.Sprintf(` LIMIT %d`, maxRuleMembers+1), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			desired[id] = true
		}
		rows.Close()
		if len(desired) > maxRuleMembers {
			// Applying a truncated result would churn members in and out.
			// The memberships are left as they are and, with the error
			// recorded, grant nothing until the rule is narrowed.
			ruleErr = fmt.Sprintf("the rule matches more than %d members", maxRuleMembers)
			_, err := tx.Exec(ctx, `UPDATE groups SET rule_recomputed_at=$2, rule_error=$3 WHERE id=$1`, groupID, s.d.Now(), ruleErr)
			return prevSkipped, err
		}
	}
	current := map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT membership_id FROM group_memberships WHERE group_id=$1 AND source='dynamic'`, groupID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		current[id] = true
	}
	rows.Close()
	members := 0
	for id := range current {
		if desired[id] {
			members++
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM group_memberships WHERE group_id=$1 AND membership_id=$2`, groupID, id); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, id); err != nil {
			return nil, err
		}
		if err := record("group.member.removed", id); err != nil {
			return nil, err
		}
	}
	groupRoles, err := groupRolesTx(ctx, tx, orgID, groupID)
	if err != nil {
		return nil, err
	}
	skipped := map[string]bool{}
	for id := range desired {
		if !current[id] {
			// A rule never combines incompatible roles (AZ-018): the member
			// is left out, with evidence, until the conflict is resolved.
			// Only the conflict itself skips a member; a failure to evaluate
			// it aborts the recomputation instead of silently skipping.
			if len(groupRoles) > 0 {
				var userID string
				if err := tx.QueryRow(ctx, `SELECT user_id FROM memberships WHERE id=$1`, id).Scan(&userID); err != nil {
					return nil, err
				}
				if err := s.Authz.CheckSeparation(ctx, tx, realmID, []string{userID}, groupRoles); err != nil {
					if !errors.Is(err, authorization.ErrIncompatibleRoles) {
						return nil, err
					}
					skipped[id] = true
					if !prevSkipped[id] {
						if err := record("group.member.skipped", id); err != nil {
							return nil, err
						}
					}
					continue
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO group_memberships (id, realm_id, organization_id, group_id, membership_id, source)
				VALUES ($1,$2,$3,$4,$5,'dynamic') ON CONFLICT (group_id, membership_id) DO NOTHING`, ids.New(ids.GroupMember), realmID, orgID, groupID, id); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE memberships SET revision=revision+1 WHERE id=$1`, id); err != nil {
				return nil, err
			}
			if err := record("group.member.added", id); err != nil {
				return nil, err
			}
			members++
		}
	}
	_, err = tx.Exec(ctx, `UPDATE groups SET rule_recomputed_at=$2, rule_member_count=$3, rule_error=nullif($4,'') WHERE id=$1`,
		groupID, s.d.Now(), members, ruleErr)
	return skipped, err
}

// RecomputeDynamicGroups recomputes up to limit dynamic groups, least
// recently recomputed first; schemaFor supplies each realm's attribute schema.
func (s *Service) RecomputeDynamicGroups(ctx context.Context, limit int, schemaFor func(ctx context.Context, realmID string) []identity.AttributeDef) (int, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, realm_id, organization_id, dynamic_rule FROM groups WHERE dynamic_rule IS NOT NULL
		ORDER BY rule_recomputed_at NULLS FIRST LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	type g struct {
		id, realm, org string
		rule           DynamicRule
	}
	var list []g
	for rows.Next() {
		var x g
		var raw []byte
		if err := rows.Scan(&x.id, &x.realm, &x.org, &raw); err != nil {
			rows.Close()
			return 0, err
		}
		_ = json.Unmarshal(raw, &x.rule)
		list = append(list, x)
	}
	rows.Close()
	n := 0
	for _, x := range list {
		rule := x.rule
		var skipped map[string]bool
		if err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			var err error
			skipped, err = s.recomputeTx(ctx, tx, x.realm, x.org, x.id, &rule, schemaFor(ctx, x.realm), audit.System, s.skips.get(x.id))
			return err
		}); err != nil {
			return n, err
		}
		s.skips.set(x.id, skipped)
		n++
	}
	return n, nil
}
