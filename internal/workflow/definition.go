package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/contracts"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// Step types: a bounded vocabulary that reuses existing services and their
// authorization, never arbitrary code (EXT-013, EXT-015).
const (
	StepWait        = "wait"
	StepApproval    = "approval"
	StepAssignRole  = "assign_role"
	StepAddToGroup  = "add_to_group"
	StepRemove      = "remove_access"
	StepNotify      = "notify"
	StepCallWebhook = "call_webhook"
	StepSuspend     = "suspend_user"
	StepEnd         = "end"
)

// Compensation strategies recorded per step attempt (EXT-016).
const (
	// CompUndo: the run reverses the effect itself (removes the role
	// assignment or group membership it created).
	CompUndo = "undo"
	// CompNone: nothing to reverse, or reversal is deliberately not automatic
	// because it would re-grant access (removals, suspensions: fail safe).
	CompNone = "none"
	// CompNotifyEndpoint: the endpoint gets a compensation call with its own
	// idempotency key.
	CompNotifyEndpoint = "notify_endpoint"
	// CompImpossible: the effect left the system (a message was sent, an
	// endpoint was called) and cannot be taken back; this is recorded.
	CompImpossible = "impossible"
)

// TriggerEvents are the outbox event types that may start a run: each names
// the user it is about in data.user_id. High-volume events (sign-ins) and
// events about non-user subjects are excluded.
var TriggerEvents = []string{
	"user.created", "user.suspended", "user.reactivated", "user.locked",
	"organization.membership.added", "organization.membership.removed",
	"organization.membership.suspended", "organization.membership.reactivated",
}

// Notices are the messages a notify step can send through the
// workflow_notice template. A definition picks a code; the text is the
// server's (and the realm's template override), never the definition's, so a
// workflow cannot be used to send arbitrary content (MSG-004).
var Notices = map[string]string{
	"welcome":            "Your account is ready.",
	"access_granted":     "Access was granted to your account.",
	"access_expiring":    "Some of your access is about to expire.",
	"access_removed":     "Some of your access was removed.",
	"approval_requested": "A request needs your approval. Review it in your account settings.",
	"account_suspended":  "Your account was suspended.",
	"offboarding":        "Your access is being removed as part of offboarding.",
}

// Limits (NFR-001): definitions are bounded in size, time and fan-out.
const (
	MaxSteps          = 20
	MaxTriggers       = 5
	MaxApprovers      = 10
	MaxWait           = 90 * 24 * time.Hour
	MaxApprovalExpiry = 30 * 24 * time.Hour
	MaxRoleExpiry     = 365 * 24 * time.Hour
	MaxBackoff        = time.Hour
	MaxAttempts       = 10
	MaxCallTimeout    = 10 * time.Second
	MinScheduleEvery  = time.Hour
	MaxScheduleEvery  = 30 * 24 * time.Hour
	// MaxScheduleSubjects bounds the runs one schedule firing starts.
	MaxScheduleSubjects = 500
	// MaxDepth bounds chains of runs started by events other runs caused.
	MaxDepth = 3
	// MaxDefinitionBytes bounds a stored definition.
	MaxDefinitionBytes = 64 << 10
)

// DefaultRetry applies to steps without a retry policy of their own.
var DefaultRetry = RetryPolicy{MaxAttempts: 3, Backoff: "30s"}

// Definition is a lifecycle workflow definition (schema_version 1,
// api/workflows/definition.v1.json).
type Definition struct {
	SchemaVersion int          `json:"schema_version"`
	Triggers      []Trigger    `json:"triggers"`
	Steps         []Step       `json:"steps"`
	Retry         *RetryPolicy `json:"retry,omitempty"`
}

// Trigger starts runs.
type Trigger struct {
	Type string `json:"type"` // event | schedule | manual
	// Event triggers.
	EventTypes     []string `json:"event_types,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	// Schedule triggers.
	Every  string    `json:"every,omitempty"`
	Select *Selector `json:"select,omitempty"`
}

// Selector picks the subjects of a scheduled firing from a fixed set of
// queries (no free-form filters).
type Selector struct {
	Type           string `json:"type"` // role_holders | organization_members
	RoleID         string `json:"role_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	// GrantedBefore keeps role holders whose assignment is at least this old
	// (access recertification), and members who joined at least this long ago.
	GrantedBefore string `json:"granted_before,omitempty"`
}

// RetryPolicy bounds the attempts of a step; the delay before attempt n+1 is
// Backoff·2^(n-1) with up to 20% jitter, capped at six hours.
type RetryPolicy struct {
	MaxAttempts int    `json:"max_attempts"`
	Backoff     string `json:"backoff"`
}

// Step is one step. Members apply to the types listed in stepMembers.
type Step struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// wait
	Duration string `json:"duration,omitempty"`
	// approval
	Approvers []string `json:"approvers,omitempty"`
	// approval expiry, or the lifetime of an assigned role
	ExpiresIn string `json:"expires_in,omitempty"`
	// assign_role, remove_access (role)
	RoleID string `json:"role_id,omitempty"`
	// realm | organization (assign_role, remove_access role)
	Scope string `json:"scope,omitempty"`
	// Pinned organization; empty uses the organization of the triggering
	// event or selector.
	OrganizationID string `json:"organization_id,omitempty"`
	// add_to_group, remove_access (group)
	GroupID string `json:"group_id,omitempty"`
	// remove_access: membership | role | group
	Access string `json:"access,omitempty"`
	// notify
	Template  string `json:"template,omitempty"`
	Notice    string `json:"notice,omitempty"`
	Recipient string `json:"recipient,omitempty"` // subject | approvers
	// call_webhook
	SubscriptionID string `json:"subscription_id,omitempty"`
	TimeoutMS      int    `json:"timeout_ms,omitempty"`
	Compensate     bool   `json:"compensate,omitempty"`
	// suspend_user, remove_access, assign_role: reason code recorded in
	// audit (and on the role assignment)
	Reason string `json:"reason,omitempty"`
	// end: succeeded (default)
	Outcome string       `json:"outcome,omitempty"`
	Retry   *RetryPolicy `json:"retry,omitempty"`
}

// stepMembers lists the members each step type accepts besides id, type and
// retry.
var stepMembers = map[string][]string{
	StepWait:        {"duration"},
	StepApproval:    {"approvers", "expires_in"},
	StepAssignRole:  {"role_id", "scope", "organization_id", "expires_in", "reason"},
	StepAddToGroup:  {"group_id", "organization_id"},
	StepRemove:      {"access", "role_id", "scope", "group_id", "organization_id", "reason"},
	StepNotify:      {"template", "notice", "recipient"},
	StepCallWebhook: {"subscription_id", "timeout_ms", "compensate"},
	StepSuspend:     {"reason"},
	StepEnd:         {"outcome"},
}

var stepID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)
var reasonCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// Compensation returns the strategy recorded for a step.
func (st Step) Compensation() string {
	switch st.Type {
	case StepAssignRole, StepAddToGroup:
		return CompUndo
	case StepNotify:
		return CompImpossible
	case StepCallWebhook:
		if st.Compensate {
			return CompNotifyEndpoint
		}
		return CompImpossible
	}
	return CompNone
}

// Policy returns the step's effective retry policy.
func (d *Definition) Policy(st Step) (int, time.Duration) {
	p := DefaultRetry
	if d.Retry != nil {
		p = *d.Retry
	}
	if st.Retry != nil {
		p = *st.Retry
	}
	// Waiting and deciding are not retried: they either complete or fail.
	if st.Type == StepWait || st.Type == StepApproval || st.Type == StepEnd {
		p.MaxAttempts = 1
	}
	b, _ := time.ParseDuration(p.Backoff)
	return p.MaxAttempts, b
}

// EventTypes returns the event types the definition's triggers listen to.
func (d *Definition) EventTypes() []string {
	var out []string
	for _, t := range d.Triggers {
		if t.Type == "event" {
			for _, e := range t.EventTypes {
				if !slices.Contains(out, e) {
					out = append(out, e)
				}
			}
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// Schedule returns the definition's schedule trigger, if any.
func (d *Definition) Schedule() (*Trigger, time.Duration) {
	for i := range d.Triggers {
		if t := &d.Triggers[i]; t.Type == "schedule" {
			every, _ := time.ParseDuration(t.Every)
			return t, every
		}
	}
	return nil, 0
}

// Manual reports whether administrators may start runs by hand.
func (d *Definition) Manual() bool {
	for _, t := range d.Triggers {
		if t.Type == "manual" {
			return true
		}
	}
	return false
}

func field(path, msg string) error { return problem.ErrValidation.WithField("definition."+path, msg) }

func duration(raw, path string, lo, hi time.Duration, required bool) error {
	if raw == "" {
		if required {
			return field(path, "required")
		}
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < lo || d > hi {
		return field(path, fmt.Sprintf("a duration between %s and %s, e.g. \"72h\"", lo, hi))
	}
	return nil
}

func validRetry(p *RetryPolicy, path string) error {
	if p == nil {
		return nil
	}
	if p.MaxAttempts < 1 || p.MaxAttempts > MaxAttempts {
		return field(path+".max_attempts", fmt.Sprintf("1..%d", MaxAttempts))
	}
	return duration(p.Backoff, path+".backoff", time.Second, MaxBackoff, true)
}

func validID(id, prefix, path string) error {
	if !ids.HasPrefix(id, prefix) {
		return field(path, "a "+prefix+"_ identifier")
	}
	return nil
}

// Parse decodes and structurally validates a definition (strict JSON:
// unknown members are refused) and returns it with its canonical form and
// hash. References (roles, groups, users, subscriptions) and the publisher's
// authority are checked separately against the realm.
func Parse(raw json.RawMessage) (*Definition, []byte, string, error) {
	if len(raw) == 0 {
		return nil, nil, "", problem.ErrValidation.WithField("definition", "required")
	}
	if len(raw) > MaxDefinitionBytes {
		return nil, nil, "", problem.ErrValidation.WithField("definition", "at most 64 KiB")
	}
	var probe struct {
		SchemaVersion int               `json:"schema_version"`
		Steps         []json.RawMessage `json:"steps"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, nil, "", problem.ErrValidation.WithField("definition", "must be a JSON object")
	}
	if !contracts.IsSupported(contracts.WorkflowDefinition, probe.SchemaVersion) {
		return nil, nil, "", field("schema_version", "supported schema versions: "+contracts.SupportedList(contracts.WorkflowDefinition))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Definition
	if err := dec.Decode(&d); err != nil {
		msg := err.Error()
		if i := strings.Index(msg, "unknown field"); i >= 0 {
			msg = msg[i:]
		} else {
			msg = "invalid member types"
		}
		return nil, nil, "", problem.ErrValidation.WithField("definition", msg)
	}
	// Members must belong to their step's type, so a definition never
	// carries settings that silently do nothing.
	for i, rawStep := range probe.Steps {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rawStep, &m); err != nil {
			return nil, nil, "", field(fmt.Sprintf("steps[%d]", i), "must be an object")
		}
		var typ string
		_ = json.Unmarshal(m["type"], &typ)
		allowed, known := stepMembers[typ]
		if !known {
			return nil, nil, "", field(fmt.Sprintf("steps[%d].type", i), "one of wait, approval, assign_role, add_to_group, remove_access, notify, call_webhook, suspend_user, end")
		}
		for k := range m {
			if k != "id" && k != "type" && k != "retry" && !slices.Contains(allowed, k) {
				return nil, nil, "", field(fmt.Sprintf("steps[%d].%s", i, k), "does not apply to "+typ+" steps")
			}
		}
	}
	if err := d.validate(); err != nil {
		return nil, nil, "", err
	}
	canon, _ := json.Marshal(d)
	sum := sha256.Sum256(canon)
	return &d, canon, hex.EncodeToString(sum[:]), nil
}

func (d *Definition) validate() error {
	if len(d.Triggers) == 0 || len(d.Triggers) > MaxTriggers {
		return field("triggers", fmt.Sprintf("1..%d triggers", MaxTriggers))
	}
	if len(d.Steps) == 0 || len(d.Steps) > MaxSteps {
		return field("steps", fmt.Sprintf("1..%d steps", MaxSteps))
	}
	if err := validRetry(d.Retry, "retry"); err != nil {
		return err
	}
	schedules := 0
	for i, t := range d.Triggers {
		p := fmt.Sprintf("triggers[%d]", i)
		switch t.Type {
		case "event":
			if len(t.EventTypes) == 0 {
				return field(p+".event_types", "at least one event type")
			}
			for _, e := range t.EventTypes {
				if !slices.Contains(TriggerEvents, e) {
					return field(p+".event_types", "triggering events: "+strings.Join(TriggerEvents, ", "))
				}
			}
			if t.OrganizationID != "" {
				if err := validID(t.OrganizationID, ids.Organization, p+".organization_id"); err != nil {
					return err
				}
			}
			if t.Every != "" || t.Select != nil {
				return field(p, "every and select apply to schedule triggers")
			}
		case "schedule":
			schedules++
			if schedules > 1 {
				return field(p, "at most one schedule trigger")
			}
			if err := duration(t.Every, p+".every", MinScheduleEvery, MaxScheduleEvery, true); err != nil {
				return err
			}
			if len(t.EventTypes) > 0 || t.OrganizationID != "" {
				return field(p, "event_types and organization_id apply to event triggers")
			}
			s := t.Select
			if s == nil {
				return field(p+".select", "required for schedule triggers")
			}
			switch s.Type {
			case "role_holders":
				if err := validID(s.RoleID, ids.Role, p+".select.role_id"); err != nil {
					return err
				}
			case "organization_members":
				if s.RoleID != "" {
					return field(p+".select.role_id", "applies to role_holders")
				}
			default:
				return field(p+".select.type", "role_holders or organization_members")
			}
			if s.OrganizationID != "" {
				if err := validID(s.OrganizationID, ids.Organization, p+".select.organization_id"); err != nil {
					return err
				}
			} else if s.Type == "organization_members" {
				return field(p+".select.organization_id", "required for organization_members")
			}
			if err := duration(s.GrantedBefore, p+".select.granted_before", 0, 10*365*24*time.Hour, false); err != nil {
				return err
			}
		case "manual":
			if len(t.EventTypes) > 0 || t.OrganizationID != "" || t.Every != "" || t.Select != nil {
				return field(p, "manual triggers take no other members")
			}
		default:
			return field(p+".type", "event, schedule or manual")
		}
	}
	seen := map[string]bool{}
	for i, st := range d.Steps {
		p := fmt.Sprintf("steps[%d]", i)
		if !stepID.MatchString(st.ID) {
			return field(p+".id", "1..40 characters a-z, 0-9, _ or -, starting with a letter")
		}
		if seen[st.ID] {
			return field(p+".id", "step ids must be unique")
		}
		seen[st.ID] = true
		if err := validRetry(st.Retry, p+".retry"); err != nil {
			return err
		}
		if st.Reason != "" && !reasonCode.MatchString(st.Reason) {
			return field(p+".reason", "an upper-case reason code such as OFFBOARDING")
		}
		if st.OrganizationID != "" {
			if err := validID(st.OrganizationID, ids.Organization, p+".organization_id"); err != nil {
				return err
			}
		}
		switch st.Type {
		case StepWait:
			if err := duration(st.Duration, p+".duration", time.Minute, MaxWait, true); err != nil {
				return err
			}
		case StepApproval:
			if len(st.Approvers) == 0 || len(st.Approvers) > MaxApprovers {
				return field(p+".approvers", fmt.Sprintf("1..%d named approvers", MaxApprovers))
			}
			for j, a := range st.Approvers {
				if err := validID(a, ids.User, fmt.Sprintf("%s.approvers[%d]", p, j)); err != nil {
					return err
				}
				if slices.Contains(st.Approvers[:j], a) {
					return field(p+".approvers", "approvers must be distinct")
				}
			}
			if err := duration(st.ExpiresIn, p+".expires_in", time.Hour, MaxApprovalExpiry, true); err != nil {
				return err
			}
		case StepAssignRole:
			if err := validID(st.RoleID, ids.Role, p+".role_id"); err != nil {
				return err
			}
			if st.Scope != "realm" && st.Scope != "organization" {
				return field(p+".scope", "realm or organization")
			}
			if st.Scope == "realm" && st.OrganizationID != "" {
				return field(p+".organization_id", "applies to organization scope")
			}
			if err := duration(st.ExpiresIn, p+".expires_in", time.Hour, MaxRoleExpiry, false); err != nil {
				return err
			}
		case StepAddToGroup:
			if err := validID(st.GroupID, ids.Group, p+".group_id"); err != nil {
				return err
			}
		case StepRemove:
			switch st.Access {
			case "membership":
				if st.RoleID != "" || st.GroupID != "" || st.Scope != "" {
					return field(p, "membership removal takes no role_id, group_id or scope")
				}
			case "role":
				if err := validID(st.RoleID, ids.Role, p+".role_id"); err != nil {
					return err
				}
				if st.Scope != "realm" && st.Scope != "organization" {
					return field(p+".scope", "realm or organization")
				}
				if st.GroupID != "" {
					return field(p+".group_id", "applies to group removal")
				}
			case "group":
				if err := validID(st.GroupID, ids.Group, p+".group_id"); err != nil {
					return err
				}
				if st.RoleID != "" || st.Scope != "" {
					return field(p, "group removal takes no role_id or scope")
				}
			default:
				return field(p+".access", "membership, role or group")
			}
		case StepNotify:
			if st.Template != "" && st.Template != "workflow_notice" {
				return field(p+".template", "workflow_notice")
			}
			if _, ok := Notices[st.Notice]; !ok {
				codes := make([]string, 0, len(Notices))
				for k := range Notices {
					codes = append(codes, k)
				}
				sort.Strings(codes)
				return field(p+".notice", "one of "+strings.Join(codes, ", "))
			}
			if st.Recipient != "" && st.Recipient != "subject" && st.Recipient != "approvers" {
				return field(p+".recipient", "subject or approvers")
			}
			if st.Recipient == "approvers" && !hasApprovalBefore(d.Steps[:i]) {
				return field(p+".recipient", "approvers requires an earlier approval step")
			}
		case StepCallWebhook:
			if err := validID(st.SubscriptionID, ids.Webhook, p+".subscription_id"); err != nil {
				return err
			}
			if st.TimeoutMS != 0 && (st.TimeoutMS < 100 || st.TimeoutMS > int(MaxCallTimeout/time.Millisecond)) {
				return field(p+".timeout_ms", "100..10000")
			}
		case StepSuspend:
		case StepEnd:
			if st.Outcome != "" && st.Outcome != "succeeded" {
				return field(p+".outcome", "succeeded")
			}
			if i != len(d.Steps)-1 {
				return field(p, "end must be the last step")
			}
		}
	}
	return nil
}

func hasApprovalBefore(steps []Step) bool {
	for _, s := range steps {
		if s.Type == StepApproval {
			return true
		}
	}
	return false
}

// orgScoped reports whether a step acts inside an organization.
func (st Step) orgScoped() bool {
	switch st.Type {
	case StepAddToGroup:
		return true
	case StepAssignRole:
		return st.Scope == "organization"
	case StepRemove:
		return st.Access == "membership" || st.Access == "group" || st.Scope == "organization"
	}
	return false
}
