package authentication

import (
	"testing"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/passkey"
	"github.com/proudauth/proudauth/internal/runtime"
)

// TestPhishingResistantFloorNeedsPasskeys covers SEC-012 and MFA-005: a
// production server refuses to start with
// security.mfa_floor.admin_phishing_resistant when it provides no passkeys,
// since sign-in could not meet the floor.
func TestPhishingResistantFloorNeedsPasskeys(t *testing.T) {
	for _, c := range []struct {
		name     string
		mode     configuration.Mode
		floor    bool
		passkeys bool
		refused  bool
	}{
		{"production floor without passkeys", configuration.ModeProduction, true, false, true},
		{"production floor with passkeys", configuration.ModeProduction, true, true, false},
		{"production without the floor", configuration.ModeProduction, false, false, false},
		{"development floor without passkeys", configuration.ModeDevelopment, true, false, false},
	} {
		cfg := &configuration.Config{Mode: c.mode}
		cfg.Security.MFAFloor.AdminPhishingResistant = c.floor
		s := &Service{d: &runtime.Deps{Cfg: cfg}}
		if c.passkeys {
			s.Passkeys = &passkey.Service{}
		}
		if err := s.CheckPhishingResistantFloor(); (err != nil) != c.refused {
			t.Errorf("%s: err=%v, refused want %v", c.name, err, c.refused)
		}
	}
}
