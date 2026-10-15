package realm

import (
	"errors"
	"testing"

	"github.com/proudauth/proudauth/internal/platform/problem"
)

// TestSMSSignInNeedsRiskAcceptance covers PWDLESS-005: SMS sign-in stays off
// unless the operator explicitly accepts its SIM-swap and delivery risks, and
// it needs phone among the permitted identifiers.
func TestSMSSignInNeedsRiskAcceptance(t *testing.T) {
	field := func(err error) string {
		var pe *problem.Error
		if !errors.As(err, &pe) {
			return ""
		}
		for k := range pe.Fields {
			return k
		}
		return ""
	}
	p := DefaultPolicy()
	if err := ValidatePolicy(p, false); err != nil {
		t.Fatalf("default policy: %v", err)
	}
	p.Login.Identifiers = append(p.Login.Identifiers, "phone")
	p.Login.SMSOTP = true
	if err := ValidatePolicy(p, false); field(err) != "login.sms_risk_accepted" {
		t.Fatalf("SMS sign-in enabled without accepting its risks: %v", err)
	}
	p.Login.SMSRiskAccepted = true
	if err := ValidatePolicy(p, false); err != nil {
		t.Fatalf("SMS sign-in with accepted risks: %v", err)
	}
	p.Login.Identifiers = []string{"email"}
	if err := ValidatePolicy(p, false); field(err) != "login.identifiers" {
		t.Fatalf("SMS sign-in without phone identifiers: %v", err)
	}
}
