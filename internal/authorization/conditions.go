package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/platform/problem"
)

// GrantConditions restrict when a role assignment applies (AZ-012). Time
// bounds use the assignment's valid_from/expires_at columns; these conditions
// cover the request-dependent parts. A condition that cannot be evaluated
// because the request context is missing fails closed: the assignment does not
// apply (AZ-007).
type GrantConditions struct {
	// ClientIDs limits the grant to tokens issued to these OAuth clients.
	ClientIDs []string `json:"client_ids,omitempty"`
	// Resources limits the grant to these API resources (IDs or audiences).
	Resources []string `json:"resources,omitempty"`
	// MinAssurance requires the session's assurance profile: "mfa" or
	// "phishing_resistant".
	MinAssurance string `json:"min_assurance,omitempty"`
	// MaxAuthAgeSeconds requires a recent authentication.
	MaxAuthAgeSeconds int `json:"max_auth_age_seconds,omitempty"`
	// ActiveHoursUTC is a daily activation window [start, end) in UTC hours;
	// start > end wraps past midnight.
	ActiveHoursUTC []int `json:"active_hours_utc,omitempty"`
	// Weekdays limits the grant to these UTC weekdays (0 = Sunday).
	Weekdays []int `json:"weekdays,omitempty"`

	// Support capability profile (IMP-002, IMP-007). On a support operator's
	// assignment these bound which organizations, target categories, support
	// modes and scopes the operator may use; they hold only for a support
	// decision context and fail closed everywhere else.
	OrganizationIDs   []string `json:"organization_ids,omitempty"`
	SubjectCategories []string `json:"subject_categories,omitempty"` // member | guest
	SupportModes      []string `json:"support_modes,omitempty"`      // read_only | allowlisted_write
	SupportScopes     []string `json:"support_scopes,omitempty"`
}

// Empty reports whether no request-dependent condition is set.
func (c GrantConditions) Empty() bool {
	return len(c.ClientIDs) == 0 && len(c.Resources) == 0 && c.MinAssurance == "" && c.MaxAuthAgeSeconds == 0 &&
		len(c.ActiveHoursUTC) == 0 && len(c.Weekdays) == 0 && !c.supportBound()
}

func (c GrantConditions) supportBound() bool {
	return len(c.OrganizationIDs) > 0 || len(c.SubjectCategories) > 0 || len(c.SupportModes) > 0 || len(c.SupportScopes) > 0
}

// ParseConditions validates a conditions document strictly.
func ParseConditions(m map[string]any) (GrantConditions, error) {
	var c GrantConditions
	if len(m) == 0 {
		return c, nil
	}
	raw, _ := json.Marshal(m)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, problem.ErrValidation.WithField("conditions", "unknown or malformed condition: allowed are client_ids, resources, min_assurance, max_auth_age_seconds, active_hours_utc, weekdays, organization_ids, subject_categories, support_modes, support_scopes")
	}
	for _, v := range c.SubjectCategories {
		if v != "member" && v != "guest" {
			return c, problem.ErrValidation.WithField("conditions.subject_categories", "member or guest")
		}
	}
	for _, v := range c.SupportModes {
		if v != "read_only" && v != "allowlisted_write" {
			return c, problem.ErrValidation.WithField("conditions.support_modes", "read_only or allowlisted_write")
		}
	}
	if len(c.OrganizationIDs) > 200 || len(c.SupportScopes) > 50 {
		return c, problem.ErrValidation.WithField("conditions", "at most 200 organizations and 50 support scopes")
	}
	switch c.MinAssurance {
	case "", "mfa", "phishing_resistant":
	default:
		return c, problem.ErrValidation.WithField("conditions.min_assurance", "mfa or phishing_resistant")
	}
	if c.MaxAuthAgeSeconds < 0 || c.MaxAuthAgeSeconds > 86400 {
		return c, problem.ErrValidation.WithField("conditions.max_auth_age_seconds", "0..86400")
	}
	if len(c.ActiveHoursUTC) != 0 && (len(c.ActiveHoursUTC) != 2 || c.ActiveHoursUTC[0] < 0 || c.ActiveHoursUTC[0] > 23 ||
		c.ActiveHoursUTC[1] < 1 || c.ActiveHoursUTC[1] > 24 || c.ActiveHoursUTC[0] == c.ActiveHoursUTC[1]) {
		return c, problem.ErrValidation.WithField("conditions.active_hours_utc", "[start 0..23, end 1..24], start != end")
	}
	for _, d := range c.Weekdays {
		if d < 0 || d > 6 {
			return c, problem.ErrValidation.WithField("conditions.weekdays", "0 (Sunday) .. 6")
		}
	}
	if len(c.ClientIDs) > 50 || len(c.Resources) > 50 {
		return c, problem.ErrValidation.WithField("conditions", "at most 50 clients or resources")
	}
	return c, nil
}

// DecisionContext is the trusted request context conditions are evaluated
// against. It is derived from validated credentials, never from request bodies
// (AZ-016).
type DecisionContext struct {
	ClientID string
	// Resources holds the target resource's ID and audience.
	Resources []string
	ACR       string
	AuthTime  time.Time
	// Support decision context (IMP-002, IMP-007), set only by the support
	// access flow from the stored request or grant.
	Support *SupportContext
}

// SupportContext describes a support-access use for capability conditions.
type SupportContext struct {
	OrganizationID  string
	SubjectCategory string
	Mode            string
	Scopes          []string
}

type decisionKey struct{}

// WithDecisionContext attaches the trusted context used for conditional grants.
func WithDecisionContext(ctx context.Context, dc DecisionContext) context.Context {
	return context.WithValue(ctx, decisionKey{}, dc)
}

// DecisionContextFrom returns the attached context, if any.
func DecisionContextFrom(ctx context.Context) (DecisionContext, bool) {
	dc, ok := ctx.Value(decisionKey{}).(DecisionContext)
	return dc, ok
}

func assuranceRank(acr string) int {
	switch {
	case strings.HasSuffix(acr, ":phishing_resistant"):
		return 3
	case strings.HasSuffix(acr, ":mfa"):
		return 2
	default:
		return 1
	}
}

// Holds evaluates the conditions. Without a decision context only purely
// time-based conditions can hold.
func (c GrantConditions) Holds(ctx context.Context, now time.Time) bool {
	if c.Empty() {
		return true
	}
	utc := now.UTC()
	if len(c.Weekdays) > 0 && !slices.Contains(c.Weekdays, int(utc.Weekday())) {
		return false
	}
	if len(c.ActiveHoursUTC) == 2 {
		h, start, end := utc.Hour(), c.ActiveHoursUTC[0], c.ActiveHoursUTC[1]
		in := (start < end && h >= start && h < end) || (start > end && (h >= start || h < end))
		if !in {
			return false
		}
	}
	needsCtx := len(c.ClientIDs) > 0 || len(c.Resources) > 0 || c.MinAssurance != "" || c.MaxAuthAgeSeconds > 0 || c.supportBound()
	if !needsCtx {
		return true
	}
	dc, ok := DecisionContextFrom(ctx)
	if !ok {
		return false
	}
	if c.supportBound() {
		sc := dc.Support
		if sc == nil {
			return false
		}
		if len(c.OrganizationIDs) > 0 && !slices.Contains(c.OrganizationIDs, sc.OrganizationID) {
			return false
		}
		if len(c.SubjectCategories) > 0 && !slices.Contains(c.SubjectCategories, sc.SubjectCategory) {
			return false
		}
		if len(c.SupportModes) > 0 && !slices.Contains(c.SupportModes, sc.Mode) {
			return false
		}
		// Every scope used must be within the operator's permitted support
		// scopes: the intersection of IMP-007.
		if len(c.SupportScopes) > 0 && (len(sc.Scopes) == 0 || slices.ContainsFunc(sc.Scopes, func(s string) bool { return !slices.Contains(c.SupportScopes, s) })) {
			return false
		}
	}
	if len(c.ClientIDs) > 0 && (dc.ClientID == "" || !slices.Contains(c.ClientIDs, dc.ClientID)) {
		return false
	}
	if len(c.Resources) > 0 && !slices.ContainsFunc(dc.Resources, func(r string) bool { return r != "" && slices.Contains(c.Resources, r) }) {
		return false
	}
	if c.MinAssurance != "" {
		need := map[string]int{"mfa": 2, "phishing_resistant": 3}[c.MinAssurance]
		if assuranceRank(dc.ACR) < need {
			return false
		}
	}
	if c.MaxAuthAgeSeconds > 0 && (dc.AuthTime.IsZero() || now.Sub(dc.AuthTime) > time.Duration(c.MaxAuthAgeSeconds)*time.Second) {
		return false
	}
	return true
}
