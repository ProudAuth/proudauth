package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/testutil"
)

// TestDoctorWarnsAboutUnenforceablePhishingResistance covers SEC-012 and
// MFA-005: a realm saved before the phishing-resistant profile required
// passkeys, with mfa.admin_phishing_resistant set and passkeys disabled,
// cannot apply the profile at sign-in; doctor reports it.
func TestDoctorWarnsAboutUnenforceablePhishingResistance(t *testing.T) {
	db := testutil.NewDB(t)
	t.Setenv("PROUDAUTH_CONFIG", "")
	t.Setenv("PROUDAUTH_MODE", "development")
	t.Setenv("PROUDAUTH_PUBLIC_ORIGIN", "http://localhost:8080")
	t.Setenv("PROUDAUTH_DATABASE_URL", db.Pool.Config().ConnString())
	t.Setenv("PROUDAUTH_ROOT_KEY", hex.EncodeToString(secret.Random(32)))
	t.Setenv("PROUDAUTH_EMAIL_ADAPTER", "dev_sink")
	if err := commands["realm-create"].run([]string{"-if-missing"}); err != nil {
		t.Fatal(err)
	}
	const warning = "WARNING realm main: phishing-resistant MFA is required"
	out, err := runbookCLI(t, "doctor")
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	if strings.Contains(out, warning) {
		t.Fatalf("warning for a realm without the profile:\n%s", out)
	}

	app, env, err := localApp("")
	if err != nil {
		t.Fatal(err)
	}
	rlm, err := app.Realms.ByName(context.Background(), "main")
	if err != nil {
		t.Fatal(err)
	}
	pol := rlm.Policy
	pol.MFA.AdminPhishingResistant = true
	pol.Login.Passkeys = false
	pol.MFA.AllowedFactors = []string{"totp", "recovery_code"}
	doc, _ := json.Marshal(pol)
	_, err = env.DB.Pool.Exec(context.Background(), `UPDATE realms SET settings=$2 WHERE id=$1`, rlm.ID, doc)
	env.DB.Close()
	if err != nil {
		t.Fatal(err)
	}
	out, err = runbookCLI(t, "doctor")
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	if !strings.Contains(out, warning) {
		t.Fatalf("no warning for a realm whose profile cannot apply:\n%s", out)
	}
}
