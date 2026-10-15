package authentication

import (
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
)

// A require_mfa flow rule never weakens a phishing-resistant requirement
// already in force, and a remembered device never answers a flow challenge.
func TestApplyFlowKeepsStrongerRequirement(t *testing.T) {
	s := &Service{}
	totp := []session.Factor{{Type: "pwd"}, {Type: "totp"}}
	fed := []session.Factor{{Type: "fed"}, {Type: "fed_mfa"}}
	passkey := []session.Factor{{Type: "pwd"}, {Type: "hwk", UserVerified: true}}
	for _, c := range []struct {
		name    string
		factors []session.Factor
		want    bool
	}{{"totp", totp, false}, {"federated mfa", fed, false}, {"verified passkey", passkey, true}} {
		tx := &Transaction{Factors: c.factors, Pending: PendingState{Flow: &FlowDecision{Outcome: realm.FlowRequireMFA}}}
		r := &requirements{mfaRequired: true, phishingResistant: true, passkeysEnabled: true}
		if s.applyFlow(tx, r) {
			t.Fatalf("%s: blocked", c.name)
		}
		if r.mfaDone != c.want || !r.phishingResistant {
			t.Errorf("%s: mfaDone=%v phishingResistant=%v, want mfaDone=%v", c.name, r.mfaDone, r.phishingResistant, c.want)
		}
	}
	tx := &Transaction{Factors: []session.Factor{{Type: "pwd"}}, Pending: PendingState{Flow: &FlowDecision{Outcome: realm.FlowChallenge}}}
	r := &requirements{mfaRequired: true, mfaDone: true, deviceRemembered: "dev_1"}
	s.applyFlow(tx, r)
	if !r.flowChallenge || r.mfaDone || r.deviceRemembered != "" {
		t.Fatalf("remembered device answered a flow challenge: %+v", r)
	}
}
