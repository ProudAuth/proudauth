package migrate

import (
	"sort"
	"time"
)

// ReportFormat names the capability report.
const ReportFormat = "proudauth.migration-report.v1"

// Outcomes of one source item.
const (
	// Converted: carried over completely.
	Converted = "converted"
	// ConvertedWithLoss: carried over, but something of it was not; the
	// reasons say what.
	ConvertedWithLoss = "converted_with_loss"
	// Unsupported: not carried over because ProudAuth cannot represent or
	// safely accept it (an algorithm or parameters outside the accepted
	// bounds, a passkey, a client secret, a flow, a role without a reviewed
	// translation).
	Unsupported = "unsupported"
	// Ignored: deliberately not carried over: excluded by the mapping, not
	// requested (--import-totp, --keep-attributes), or without meaning in
	// ProudAuth (Keycloak default roles).
	Ignored = "ignored"
)

// Report is the capability report of one conversion (MIG-018). It names
// source records by their source IDs only: it never contains credentials,
// seeds or contact data.
type Report struct {
	Format       string                   `json:"format"`
	GeneratedAt  time.Time                `json:"generated_at"`
	Source       SourceInfo               `json:"source"`
	SourceSystem string                   `json:"source_system"`
	Options      ReportOptions            `json:"options"`
	Summary      Summary                  `json:"summary"`
	Entities     map[string]*EntityReport `json:"entities"`
	Mapping      MappingReview            `json:"mapping"`
	Items        []Item                   `json:"items"`
	Notes        []string                 `json:"notes,omitempty"`
	// Import is filled when the documents were submitted (a dry run or the
	// real import): the server's per-record outcome.
	Import *ImportOutcome `json:"import,omitempty"`
}

// ReportOptions records the choices that shaped the conversion.
type ReportOptions struct {
	ImportTOTP     bool `json:"import_totp"`
	KeepAttributes bool `json:"keep_attributes"`
	MappingGiven   bool `json:"mapping_given"`
}

// Summary gives the numbers an operator checks first.
type Summary struct {
	Users                    int `json:"users"`
	UsersToImport            int `json:"users_to_import"`
	PasswordsMigrated        int `json:"passwords_migrated"`
	PasswordResetsRequired   int `json:"password_resets_required"`
	TOTPMigrated             int `json:"totp_migrated"`
	MFAReenrollmentsRequired int `json:"mfa_reenrollments_required"`
	SuspendedAccounts        int `json:"suspended_accounts"`
	Organizations            int `json:"organizations"`
	Memberships              int `json:"memberships"`
	RoleAssignments          int `json:"role_assignments"`
	UntranslatedRoleGrants   int `json:"untranslated_role_grants"`
}

// EntityReport counts one entity type by outcome; Reasons aggregates why
// items were not simply converted.
type EntityReport struct {
	Total             int           `json:"total"`
	Converted         int           `json:"converted"`
	ConvertedWithLoss int           `json:"converted_with_loss"`
	Unsupported       int           `json:"unsupported"`
	Ignored           int           `json:"ignored"`
	Reasons           []ReasonCount `json:"reasons,omitempty"`
}

// ReasonCount is one reason with the number of items it applies to.
type ReasonCount struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
	Count   int    `json:"count"`
}

// Item is one source item that was not simply converted.
type Item struct {
	Entity   string   `json:"entity"`
	SourceID string   `json:"source_id"`
	Outcome  string   `json:"outcome"`
	Reasons  []string `json:"reasons"`
}

// MappingReview shows how each source organization and role key was
// translated, for review before the import (MIG-005).
type MappingReview struct {
	Organizations []OrgReview  `json:"organizations"`
	Roles         []RoleReview `json:"roles"`
	// UnknownKeys are mapping entries that match nothing in the export.
	UnknownKeys []string `json:"unknown_keys,omitempty"`
}

// OrgReview is the translation of one source organization key.
type OrgReview struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Status  string `json:"status"` // auto, mapped, excluded, not_an_organization
	Slug    string `json:"slug,omitempty"`
	Members int    `json:"members"`
}

// RoleReview is the translation of one source role key.
type RoleReview struct {
	Key          string   `json:"key"`
	Note         string   `json:"note,omitempty"`
	Grants       int      `json:"grants"`
	Status       string   `json:"status"` // mapped, no_roles, untranslated, ignored
	Organization string   `json:"organization,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// ImportOutcome is what the server reported for the submitted documents.
type ImportOutcome struct {
	DryRun        bool            `json:"dry_run"`
	Jobs          []string        `json:"jobs"`
	Counts        map[string]int  `json:"counts"`
	Totals        map[string]int  `json:"totals"`
	Organizations []OrgOutcome    `json:"organizations"`
	Records       []RecordOutcome `json:"records,omitempty"`
	// Expected holds the counts of the converted export a real import is
	// reconciled against (users, memberships, password_verifiers,
	// totp_factors; sent as the expected_* parameters), and Reconciliation
	// the GET /user-imports/reconciliation answer.
	Expected       map[string]int `json:"expected,omitempty"`
	Reconciliation map[string]any `json:"reconciliation,omitempty"`
}

// OrgOutcome is what happened to one target organization.
type OrgOutcome struct {
	Slug   string `json:"slug"`
	ID     string `json:"id,omitempty"`
	Status string `json:"status"` // exists, created, will_create, conflict
	Detail string `json:"detail,omitempty"`
}

// RecordOutcome is the server's result for a record that was not imported
// (already_imported, conflict, skipped_deleted, error).
type RecordOutcome struct {
	SourceID string `json:"source_id"`
	Status   string `json:"status"`
	UserID   string `json:"user_id,omitempty"`
	Error    string `json:"error,omitempty"`
}

type reportBuilder struct {
	r       *Report
	reasons map[string]map[[2]string]int
}

func newReportBuilder(info SourceInfo, sourceSystem string, opts Options) *reportBuilder {
	return &reportBuilder{r: &Report{Format: ReportFormat, GeneratedAt: opts.Now().UTC(), Source: info, SourceSystem: sourceSystem,
		Options:  ReportOptions{ImportTOTP: opts.ImportTOTP, KeepAttributes: opts.KeepAttributes, MappingGiven: opts.Mapping != nil && (len(opts.Mapping.Organizations) > 0 || len(opts.Mapping.Roles) > 0 || len(opts.Mapping.MembershipRoles) > 0)},
		Entities: map[string]*EntityReport{}, Items: []Item{}, Mapping: MappingReview{Organizations: []OrgReview{}, Roles: []RoleReview{}}},
		reasons: map[string]map[[2]string]int{}}
}

// add records one item of an entity. Items that were not simply converted
// are listed with their reasons.
func (b *reportBuilder) add(entity, sourceID, outcome string, reasons ...string) {
	b.addN(entity, outcome, 1, reasons...)
	if outcome != Converted {
		b.r.Items = append(b.r.Items, Item{Entity: entity, SourceID: sourceID, Outcome: outcome, Reasons: append([]string{}, reasons...)})
	}
}

// addN counts n items of an entity without listing them.
func (b *reportBuilder) addN(entity, outcome string, n int, reasons ...string) {
	if n == 0 {
		return
	}
	e := b.r.Entities[entity]
	if e == nil {
		e = &EntityReport{}
		b.r.Entities[entity] = e
	}
	e.Total += n
	switch outcome {
	case Converted:
		e.Converted += n
	case ConvertedWithLoss:
		e.ConvertedWithLoss += n
	case Unsupported:
		e.Unsupported += n
	case Ignored:
		e.Ignored += n
	}
	if outcome == Converted {
		return
	}
	m := b.reasons[entity]
	if m == nil {
		m = map[[2]string]int{}
		b.reasons[entity] = m
	}
	for _, r := range reasons {
		m[[2]string{outcome, r}] += n
	}
}

func (b *reportBuilder) note(s string) { b.r.Notes = append(b.r.Notes, s) }

func (b *reportBuilder) finish() *Report {
	for entity, m := range b.reasons {
		list := make([]ReasonCount, 0, len(m))
		for k, n := range m {
			list = append(list, ReasonCount{Outcome: k[0], Reason: k[1], Count: n})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count != list[j].Count {
				return list[i].Count > list[j].Count
			}
			if list[i].Outcome != list[j].Outcome {
				return list[i].Outcome < list[j].Outcome
			}
			return list[i].Reason < list[j].Reason
		})
		b.r.Entities[entity].Reasons = list
	}
	sort.SliceStable(b.r.Items, func(i, j int) bool {
		if b.r.Items[i].Entity != b.r.Items[j].Entity {
			return b.r.Items[i].Entity < b.r.Items[j].Entity
		}
		return b.r.Items[i].SourceID < b.r.Items[j].SourceID
	})
	return b.r
}

// Entity returns the counts of an entity (zero counts when absent).
func (r *Report) Entity(name string) EntityReport {
	if e := r.Entities[name]; e != nil {
		return *e
	}
	return EntityReport{}
}

// ItemsFor returns the listed items of a source record.
func (r *Report) ItemsFor(sourceID string) []Item {
	var out []Item
	for _, it := range r.Items {
		if it.SourceID == sourceID {
			out = append(out, it)
		}
	}
	return out
}
