package realm

import (
	"net/netip"
	"slices"
	"testing"
)

func codes(fs []FlowFinding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.Code+":"+f.Rule)
	}
	return out
}

func TestAnalyzeFlow(t *testing.T) {
	yes := true
	cases := []struct {
		name     string
		rules    []AuthFlowRule
		errors   []string
		warnings []string
	}{
		{"allow everything shadows privileged mfa", []AuthFlowRule{
			{Name: "all", Outcome: FlowAllow},
			{Name: "admins", When: AuthFlowCondition{Privileged: &yes}, Outcome: FlowRequireMFA},
		}, []string{"bypass:admins"}, nil},
		{"client superset shadows stricter client rule", []AuthFlowRule{
			{Name: "apps", When: AuthFlowCondition{Clients: []string{"a", "b"}}, Outcome: FlowReview},
			{Name: "a", When: AuthFlowCondition{Clients: []string{"a"}}, Outcome: FlowDeny},
		}, []string{"bypass:a"}, nil},
		{"lower assurance bound shadows", []AuthFlowRule{
			{Name: "below pr", When: AuthFlowCondition{AssuranceBelow: "urn:proudauth:acr:phishing_resistant"}, Outcome: FlowAllow},
			{Name: "below mfa", When: AuthFlowCondition{AssuranceBelow: "urn:proudauth:acr:mfa"}, Outcome: FlowRequireMFA},
		}, []string{"bypass:below mfa"}, nil},
		{"risk allow is reachable through a missing signal", []AuthFlowRule{
			{Name: "low", When: AuthFlowCondition{RiskAtLeast: "low"}, Outcome: FlowAllow},
			{Name: "medium", When: AuthFlowCondition{RiskAtLeast: "medium"}, Outcome: FlowDeny},
		}, nil, []string{"partial_bypass:medium"}},
		{"network allow covers skip-on-missing rule", []AuthFlowRule{
			{Name: "office", When: AuthFlowCondition{Networks: []string{"10.0.0.0/8"}}, Outcome: FlowAllow},
			{Name: "lab", When: AuthFlowCondition{Networks: []string{"10.1.0.0/16"}}, Outcome: FlowRequireMFA, OnMissingSignal: "skip"},
		}, []string{"bypass:lab"}, nil},
		{"stricter earlier rule makes later one dead", []AuthFlowRule{
			{Name: "mfa", Outcome: FlowRequireMFA},
			{Name: "new device", When: AuthFlowCondition{NewDevice: &yes}, Outcome: FlowChallenge},
		}, nil, []string{"unreachable:new device"}},
		{"disjoint clients do not interact", []AuthFlowRule{
			{Name: "a", When: AuthFlowCondition{Clients: []string{"a"}}, Outcome: FlowAllow},
			{Name: "b", When: AuthFlowCondition{Clients: []string{"b"}}, Outcome: FlowDeny},
		}, nil, nil},
		{"outside networks exclude", []AuthFlowRule{
			{Name: "outside office", When: AuthFlowCondition{OutsideNetworks: []string{"10.0.0.0/8"}}, Outcome: FlowAllow},
			{Name: "office", When: AuthFlowCondition{Networks: []string{"10.2.0.0/16"}}, Outcome: FlowRequireMFA},
		}, nil, nil},
		{"unconditional deny", []AuthFlowRule{{Name: "lockdown", Outcome: FlowDeny}}, nil, []string{"deny_all:lockdown"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := AnalyzeFlow(AuthFlowPolicy{Rules: c.rules})
			if got := codes(a.Errors); !slices.Equal(got, append([]string{}, c.errors...)) {
				t.Errorf("errors = %v, want %v", got, c.errors)
			}
			if got := codes(a.Warnings); !slices.Equal(got, append([]string{}, c.warnings...)) {
				t.Errorf("warnings = %v, want %v", got, c.warnings)
			}
			if (len(c.errors) > 0) != (a.Problem() != nil) {
				t.Errorf("problem = %v", a.Problem())
			}
		})
	}
}

type facts struct {
	ip   string
	risk string
}

func (facts) ClientID() string            { return "web" }
func (facts) OrganizationID() string      { return "" }
func (facts) Method() string              { return "password" }
func (facts) ResourceAudiences() []string { return nil }
func (facts) KnownDevice() bool           { return true }
func (facts) FailedAttempts() int         { return 0 }
func (facts) Privileged() bool            { return false }
func (facts) AssuranceBelow(string) bool  { return true }
func (f facts) ClientAddr() (netip.Addr, bool) {
	ip, err := netip.ParseAddr(f.ip)
	return ip, err == nil
}
func (f facts) RiskAtLeast(level string) (bool, bool) {
	if f.risk == "" {
		return false, false
	}
	return slices.Index(RiskLevels, f.risk) >= slices.Index(RiskLevels, level), true
}

func TestEvaluateFlowMissingSignals(t *testing.T) {
	p := AuthFlowPolicy{Rules: []AuthFlowRule{
		{Name: "office", When: AuthFlowCondition{Networks: []string{"10.0.0.0/8"}}, Outcome: FlowAllow},
		{Name: "risky", When: AuthFlowCondition{RiskAtLeast: "high"}, Outcome: FlowDeny, OnMissingSignal: "skip"},
		{Name: "rest", Outcome: FlowRequireMFA},
	}}
	for _, c := range []struct {
		f       facts
		outcome string
		rule    string
		missing []string
	}{
		{facts{ip: "10.1.2.3", risk: "high"}, FlowAllow, "office", nil},
		{facts{ip: "192.0.2.1", risk: "high"}, FlowDeny, "risky", nil},
		{facts{ip: "192.0.2.1"}, FlowRequireMFA, "rest", []string{"risk"}},
		{facts{risk: "low"}, FlowRequireMFA, "rest", []string{"network"}},
	} {
		got := EvaluateFlow(p, c.f)
		if got.Outcome != c.outcome || got.Rule != c.rule || !slices.Equal(got.Missing, c.missing) {
			t.Errorf("%+v: got %+v", c.f, got)
		}
	}
}

// TestRiskNeverOverridesDeny covers ADV-012: a risk verdict, however low,
// cannot undo an explicit deny that matches first, and analysis flags an
// allow-on-low-risk rule placed ahead of a stricter rule.
func TestRiskNeverOverridesDeny(t *testing.T) {
	p := AuthFlowPolicy{Rules: []AuthFlowRule{
		{Name: "blocked network", When: AuthFlowCondition{Networks: []string{"198.51.100.0/24"}}, Outcome: FlowDeny},
		{Name: "low risk", When: AuthFlowCondition{RiskAtLeast: "low"}, Outcome: FlowAllow},
		{Name: "everyone else", Outcome: FlowRequireMFA},
	}}
	if got := EvaluateFlow(p, facts{ip: "198.51.100.7", risk: "low"}); got.Outcome != FlowDeny {
		t.Fatalf("low risk overrode an explicit deny: %+v", got)
	}
	// Without a risk verdict the allow rule never matches; the stricter
	// rule applies.
	if got := EvaluateFlow(p, facts{ip: "203.0.113.9"}); got.Outcome != FlowRequireMFA {
		t.Fatalf("missing risk signal relaxed the requirement: %+v", got)
	}
	a := AnalyzeFlow(p)
	if !slices.ContainsFunc(a.Warnings, func(f FlowFinding) bool { return f.Code == "partial_bypass" && f.Rule == "everyone else" }) {
		t.Fatalf("allow-on-risk ahead of a stricter rule not reported: %+v", a)
	}
}
