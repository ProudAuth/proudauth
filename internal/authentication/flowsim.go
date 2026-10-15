package authentication

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
)

// FlowCase is one simulated sign-in (AUT-019). An empty ip or risk is a
// missing signal, as for a sign-in without a client address or without a
// risk verdict, so simulation shows how missing signals are treated.
type FlowCase struct {
	Name           string   `json:"name,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	Method         string   `json:"method,omitempty"`
	Resources      []string `json:"resources,omitempty"`
	IP             string   `json:"ip,omitempty"`
	KnownDevice    bool     `json:"known_device,omitempty"`
	FailedAttempts int      `json:"failed_attempts,omitempty"`
	Risk           string   `json:"risk,omitempty"`
	// RiskPartial marks the risk as a lower bound (a hook that timed out
	// after reporting a level).
	RiskPartial bool `json:"risk_partial,omitempty"`
	Privileged  bool `json:"privileged,omitempty"`
	// Assurance is the ACR reached before the flow is evaluated; empty is
	// single factor.
	Assurance string `json:"assurance,omitempty"`
}

// FlowSimulation compares the live flow and a candidate for one case.
type FlowSimulation struct {
	Case      string           `json:"case"`
	Current   realm.FlowResult `json:"current"`
	Candidate realm.FlowResult `json:"candidate"`
	// Change is unchanged, stricter, weaker or rule_changed (same outcome
	// from a different rule).
	Change string `json:"change"`
}

const maxFlowCases = 200

// SimulateFlow evaluates every case against the live and the candidate flow
// with the evaluator sign-in uses.
func SimulateFlow(current, candidate realm.AuthFlowPolicy, cases []FlowCase) ([]FlowSimulation, error) {
	if len(cases) == 0 || len(cases) > maxFlowCases {
		return nil, problem.ErrValidation.WithField("cases", fmt.Sprintf("1 to %d cases", maxFlowCases))
	}
	out := make([]FlowSimulation, 0, len(cases))
	for i, c := range cases {
		field := func(name string) string { return fmt.Sprintf("cases[%d].%s", i, name) }
		if c.Method != "" && !slices.Contains(realm.FlowMethods, c.Method) {
			return nil, problem.ErrValidation.WithField(field("method"), "one of the flow methods")
		}
		if c.Risk != "" && !slices.Contains(realm.RiskLevels, c.Risk) {
			return nil, problem.ErrValidation.WithField(field("risk"), "low, medium or high")
		}
		if c.IP != "" {
			if _, err := netip.ParseAddr(c.IP); err != nil {
				return nil, problem.ErrValidation.WithField(field("ip"), "an IP address")
			}
		}
		if c.Assurance != "" && session.ACRRank(c.Assurance) == 0 {
			return nil, problem.ErrValidation.WithField(field("assurance"), "an assurance profile such as urn:proudauth:acr:mfa")
		}
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("case %d", i+1)
		}
		f := caseFacts{c}
		sim := FlowSimulation{Case: name, Current: realm.EvaluateFlow(current, f), Candidate: realm.EvaluateFlow(candidate, f)}
		switch a, b := realm.FlowStrength(sim.Current.Outcome), realm.FlowStrength(sim.Candidate.Outcome); {
		case b > a:
			sim.Change = "stricter"
		case b < a:
			sim.Change = "weaker"
		case sim.Current.Outcome != sim.Candidate.Outcome || sim.Current.Rule != sim.Candidate.Rule:
			sim.Change = "rule_changed"
		default:
			sim.Change = "unchanged"
		}
		out = append(out, sim)
	}
	return out, nil
}

// caseFacts implements realm.FlowFacts for a simulated sign-in.
type caseFacts struct{ c FlowCase }

func (f caseFacts) ClientID() string            { return f.c.ClientID }
func (f caseFacts) OrganizationID() string      { return f.c.OrganizationID }
func (f caseFacts) Method() string              { return f.c.Method }
func (f caseFacts) ResourceAudiences() []string { return f.c.Resources }
func (f caseFacts) KnownDevice() bool           { return f.c.KnownDevice }
func (f caseFacts) FailedAttempts() int         { return f.c.FailedAttempts }
func (f caseFacts) Privileged() bool            { return f.c.Privileged }

func (f caseFacts) ClientAddr() (netip.Addr, bool) {
	ip, err := netip.ParseAddr(f.c.IP)
	return ip, err == nil
}

func (f caseFacts) AssuranceBelow(acr string) bool {
	have := f.c.Assurance
	if have == "" {
		have = "urn:proudauth:acr:single_factor"
	}
	return session.ACRRank(have) < session.ACRRank(acr)
}

func (f caseFacts) RiskAtLeast(level string) (bool, bool) {
	if f.c.Risk == "" {
		return false, false
	}
	if riskRank[f.c.Risk] >= riskRank[level] {
		return true, true
	}
	return false, !f.c.RiskPartial
}
