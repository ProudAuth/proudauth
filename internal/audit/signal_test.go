package audit

import "testing"

func TestSecuritySignal(t *testing.T) {
	for _, c := range []struct {
		ev   Event
		want string
	}{
		{Event{Type: "token.refresh.reuse_detected"}, "refresh_reuse"},
		{Event{Type: "support.impersonation.denied"}, "impersonation_denied"},
		{Event{Type: "authorization.decision", ReasonCode: "ORGANIZATION_MISMATCH"}, "cross_tenant_denial"},
		{Event{Type: "recovery.assisted"}, "factor_recovery"},
		{Event{Type: "signing_key.rotated"}, "signing_key_change"},
		{Event{Type: "signing_key.activated"}, ""},
		{Event{Type: "bootstrap.break_glass_admin_created"}, "bootstrap"},
		{Event{Type: "automation_credential.created"}, "credential_issued"},
		{Event{Type: "user.updated"}, ""},
	} {
		if got := SecuritySignal(c.ev); got != c.want {
			t.Errorf("%s/%s: got %q, want %q", c.ev.Type, c.ev.ReasonCode, got, c.want)
		}
	}
}
