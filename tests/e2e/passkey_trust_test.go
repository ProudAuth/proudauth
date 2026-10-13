package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/passkey"
	"github.com/proudbase/proudauth/internal/realm"
)

// attester is a test authenticator vendor: a root CA and a packed
// attestation certificate for one AAGUID.
type attester struct {
	rootPEM string
	key     *ecdsa.PrivateKey
	cert    []byte
}

func newAttester(t testing.TB, aaguid []byte) *attester {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Authenticator Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ext, _ := asn1.Marshal(aaguid)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Test Vendor"}, OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Test Key"},
		BasicConstraintsValid: true, IsCA: false,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: ext}}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, rootCert, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return &attester{rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})), key: key, cert: leafDER}
}

// packed builds a packed attestation object signed by the attestation key.
func (a *attester) packed(t testing.TB, authData, clientDataJSON []byte) []byte {
	cdh := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, authData...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := cbor.Marshal(map[string]any{"fmt": "packed", "attStmt": map[string]any{"alg": -7, "sig": sig, "x5c": [][]byte{a.cert}}, "authData": authData})
	return out
}

const testAAGUID = "6a1f3c2e-9b4d-4e8a-a1b2-0c3d4e5f6a7b"

func aaguidBytes(s string) []byte {
	b := make([]byte, 0, 16)
	h := strings.ReplaceAll(s, "-", "")
	for i := 0; i < len(h); i += 2 {
		var v byte
		for _, c := range h[i : i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'a') + 10
			}
		}
		b = append(b, v)
	}
	return b
}

// TestPasskeyAttestationTrust covers PASS-009: attestation is off by
// default; a realm can require attestation chaining to trusted metadata
// (its own trusted authenticators), restrict authenticator models at
// registration and sign-in, and record the trust result per credential.
func TestPasskeyAttestationTrust(t *testing.T) {
	f := NewFixture(t, passkeyPolicy)
	h := f.H
	enroll := func(user string, key *softKey) *Resp {
		t.Helper()
		f.CreateUser(user)
		tok := f.AccountToken(user).Tokens.Str("access_token")
		opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
		mustStatus(t, opts, 200, "registration options")
		return h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
			"credential": key.create(t, opts.Get("public_key")), "name": "key"})
	}
	// Privacy-conscious default: no attestation is requested.
	f.CreateUser("pat")
	opts := h.API("POST", "/me/webauthn/registration-options", f.AccountToken("pat").Tokens.Str("access_token"), map[string]any{})
	if a := opts.Str("public_key.attestation"); a != "none" && a != "" {
		t.Fatalf("attestation requested by default: %s", a)
	}

	// Policy validation.
	for name, mut := range map[string]func(p *realm.Policy){
		"trusted without direct": func(p *realm.Policy) { p.WebAuthn.RequireTrustedAttestation = true },
		"bad attestation":        func(p *realm.Policy) { p.WebAuthn.Attestation = "always" },
		"bad aaguid":             func(p *realm.Policy) { p.WebAuthn.BlockedAAGUIDs = []string{"not-a-uuid"} },
		"both lists": func(p *realm.Policy) {
			p.WebAuthn.AllowedAAGUIDs, p.WebAuthn.BlockedAAGUIDs = []string{testAAGUID}, []string{testAAGUID}
		},
		"related origins off": func(p *realm.Policy) { p.WebAuthn.RelatedOrigins = []string{"https://shop.test"} },
		"credProtect value":   func(p *realm.Policy) { p.WebAuthn.CredentialProtection = "always" },
	} {
		if r := f.SetPolicy(mut); r.Status != 422 {
			t.Fatalf("%s accepted: %d %s", name, r.Status, r.Raw)
		}
	}

	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.WebAuthn.Attestation, p.WebAuthn.RequireTrustedAttestation = "direct", true
	}), 200, "require trusted attestation")
	vendor := newAttester(t, aaguidBytes(testAAGUID))
	trustedKey := func() *softKey {
		k := newSoftKey("login.test", "https://login.test", false)
		k.aaguid, k.att = aaguidBytes(testAAGUID), vendor
		return k
	}
	// Without trusted metadata, nothing can register.
	if r := enroll("pkuser1", trustedKey()); r.Status == 201 {
		t.Fatalf("registered without trusted metadata: %s", r.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/webauthn/trusted-authenticators", map[string]any{"aaguid": "00000000-0000-0000-0000-000000000000",
		"description": "zero", "root_certificates": []string{vendor.rootPEM}}), 422, "zero AAGUID")
	mustStatus(t, f.AdminAPI("POST", "/webauthn/trusted-authenticators", map[string]any{"aaguid": testAAGUID, "description": "Leaf",
		"root_certificates": []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}}), 422, "bad PEM")
	ta := f.must(f.AdminAPI("POST", "/webauthn/trusted-authenticators", map[string]any{"aaguid": testAAGUID, "description": "Test Vendor Key",
		"root_certificates": []string{vendor.rootPEM}}), 201, "trust model")
	mustStatus(t, f.AdminAPI("POST", "/webauthn/trusted-authenticators", map[string]any{"aaguid": testAAGUID, "description": "again",
		"root_certificates": []string{vendor.rootPEM}}), 409, "duplicate")

	good := trustedKey()
	r := enroll("pkuser2", good)
	mustStatus(t, r, 201, "trusted registration")
	if r.Get("attestation_trusted") != true || r.Str("attestation_format") != "packed" || r.Str("aaguid") != testAAGUID {
		t.Fatalf("credential: %s", r.Raw)
	}
	// No attestation, a foreign chain, or an unknown model are refused.
	if r := enroll("pkuser3", newSoftKey("login.test", "https://login.test", false)); r.Status != 422 || !strings.Contains(string(r.Raw), "attestation_not_trusted") {
		t.Fatalf("none attestation: %d %s", r.Status, r.Raw)
	}
	forged := trustedKey()
	forged.att = newAttester(t, aaguidBytes(testAAGUID))
	if r := enroll("pkuser4", forged); r.Status == 201 {
		t.Fatalf("attestation from an untrusted root accepted: %s", r.Raw)
	}
	other := "0f1e2d3c-4b5a-4968-8776-655443322110"
	unknown := newSoftKey("login.test", "https://login.test", false)
	unknown.aaguid, unknown.att = aaguidBytes(other), newAttester(t, aaguidBytes(other))
	if r := enroll("pkuser5", unknown); r.Status == 201 {
		t.Fatalf("model without metadata accepted: %s", r.Raw)
	}

	// Blocking the model stops sign-in with already enrolled passkeys.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.WebAuthn.BlockedAAGUIDs = []string{testAAGUID} }), 200, "block model")
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	start, _, cont := h.StartTx(cli)
	tx := start.Str("transaction_id")
	o := h.Step(tx, cont, "webauthn/options", nil)
	if res := h.Step(tx, cont, "webauthn/verify", map[string]any{"credential": good.get(t, o.Get("webauthn.public_key"))}); res.Status == 200 {
		t.Fatalf("blocked model signed in: %s", res.Raw)
	}
	// An allow list refuses unnamed (zero AAGUID) authenticators.
	f.ReloginAdmin()
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.WebAuthn.BlockedAAGUIDs, p.WebAuthn.AllowedAAGUIDs = nil, []string{testAAGUID}
		p.WebAuthn.Attestation, p.WebAuthn.RequireTrustedAttestation = "", false
	}), 200, "allow list")
	if r := enroll("pkuser6", newSoftKey("login.test", "https://login.test", false)); r.Status != 422 || !strings.Contains(string(r.Raw), "authenticator_not_allowed") {
		t.Fatalf("zero AAGUID under an allow list: %d %s", r.Status, r.Raw)
	}
	list := f.must(f.AdminAPI("GET", "/webauthn/trusted-authenticators", nil), 200, "list")
	if len(list.Get("items").([]any)) != 1 {
		t.Fatalf("trusted list: %s", list.Raw)
	}
	mustStatus(t, f.AdminAPI("DELETE", "/webauthn/trusted-authenticators/"+ta.Str("id"), nil), 204, "remove")
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=mfa.webauthn.enrolled", nil), 200, "audit")
	if !strings.Contains(string(ev.Raw), `"attestation_trusted":true`) && !strings.Contains(string(ev.Raw), `"attestation_trusted": true`) {
		t.Fatalf("trust not audited: %s", ev.Raw)
	}
}

// TestPasskeyAdvancedCapabilities covers PASS-010: related origins only
// when the operator allows them, published at /.well-known/webauthn and
// accepted in ceremonies; credProtect requested and enforced.
func TestPasskeyAdvancedCapabilities(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.WebAuthn.RelatedOrigins = true })
	f := fixtureOn(t, h, passkeyPolicy)
	if r := h.Do(Req{Method: "GET", Path: "/.well-known/webauthn", Headers: map[string]string{"Host": "login.test"}}); r.Status != 404 {
		t.Fatalf("related origins served before any realm declared them: %d", r.Status)
	}
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.WebAuthn.RelatedOrigins = []string{"https://a.test", "https://b.test", "https://c.test", "https://d.test", "https://e.test"}
	}), 422, "six registrable domains")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.WebAuthn.RelatedOrigins = []string{"http://shop.test"} }), 422, "http origin")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.WebAuthn.RelatedOrigins = []string{"https://shop.test"} }), 200, "related origin")
	doc := h.Do(Req{Method: "GET", Path: "/.well-known/webauthn", Headers: map[string]string{"Host": "login.test"}})
	mustStatus(t, doc, 200, "well-known")
	origins := jsonString(doc.Get("origins"))
	if !strings.Contains(origins, "https://shop.test") || !strings.Contains(origins, "https://login.test") {
		t.Fatalf("related origins document: %s", doc.Raw)
	}
	if r := h.Do(Req{Method: "GET", Path: "/.well-known/webauthn", Headers: map[string]string{"Host": "other.test"}}); r.Status != 404 {
		t.Fatalf("document served for another host: %d", r.Status)
	}
	enroll := func(user string, key *softKey) *Resp {
		t.Helper()
		f.CreateUser(user)
		tok := f.AccountToken(user).Tokens.Str("access_token")
		opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
		mustStatus(t, opts, 200, "registration options")
		return h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
			"credential": key.create(t, opts.Get("public_key")), "name": "key"})
	}
	mustStatus(t, enroll("roguser1", newSoftKey("login.test", "https://shop.test", false)), 201, "registration from a related origin")
	if r := enroll("roguser2", newSoftKey("login.test", "https://elsewhere.test", false)); r.Status == 201 {
		t.Fatal("registration from an undeclared origin")
	}

	// credProtect: requested in the options; enforced, an authenticator that
	// does not apply it is refused.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.WebAuthn.CredentialProtection, p.WebAuthn.EnforceCredentialProtection = "userVerificationRequired", true
	}), 200, "credProtect")
	f.CreateUser("roguser3")
	tok := f.AccountToken("roguser3").Tokens.Str("access_token")
	opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
	if opts.Str("public_key.extensions.credentialProtectionPolicy") != "userVerificationRequired" || opts.Get("public_key.extensions.enforceCredentialProtectionPolicy") != true {
		t.Fatalf("credProtect not requested: %s", opts.Raw)
	}
	plain := newSoftKey("login.test", "https://login.test", false)
	if r := h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
		"credential": plain.create(t, opts.Get("public_key"))}); r.Status == 201 {
		t.Fatalf("authenticator without credProtect accepted: %s", r.Raw)
	}
	protected := newSoftKey("login.test", "https://login.test", false)
	protected.credProtect = 3
	mustStatus(t, enroll("roguser4", protected), 201, "credProtect honoured")
	_ = http.StatusOK
}

// buildMDSBlob writes a FIDO MDS3 BLOB listing one authenticator model,
// signed by a test metadata root, and that root as PEM. It returns both
// paths.
func buildMDSBlob(t *testing.T, aaguid, attestationRootPEM string, signer *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	dir := t.TempDir()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if signer == nil {
		signer = rootKey
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Test MDS Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	attBlock, _ := pem.Decode([]byte(attestationRootPEM))
	payload := map[string]any{"legalHeader": "test metadata", "no": 1, "nextUpdate": "2099-01-01", "entries": []any{map[string]any{
		"aaguid": aaguid, "timeOfLastStatusChange": "2026-01-01",
		"statusReports": []any{map[string]any{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2026-01-01"}},
		"metadataStatement": map[string]any{"description": "Test Vendor Key", "aaguid": aaguid, "schema": 3, "attestationTypes": []string{"basic_full"},
			"attestationRootCertificates": []string{base64.StdEncoding.EncodeToString(attBlock.Bytes)}}}}}
	body, _ := json.Marshal(payload)
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT"})
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	blob := filepath.Join(dir, "blob.jwt")
	root := filepath.Join(dir, "root.pem")
	if err := os.WriteFile(blob, []byte(signing+"."+base64.RawURLEncoding.EncodeToString(sig)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return blob, root
}

// TestPasskeyFIDOMetadata covers PASS-009 trusted metadata from the
// operator's FIDO MDS3 BLOB: verified against the configured root at
// startup, and then trusted for registrations that require trusted
// attestation; a BLOB not signed by the root stops startup.
func TestPasskeyFIDOMetadata(t *testing.T) {
	vendor := newAttester(t, aaguidBytes(testAAGUID))
	blob, root := buildMDSBlob(t, testAAGUID, vendor.rootPEM, nil)
	h := NewHarness(t, func(c *configuration.Config) { c.WebAuthn.MetadataFile, c.WebAuthn.MetadataRootFile = blob, root })
	f := fixtureOn(t, h, passkeyPolicy)
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.WebAuthn.Attestation, p.WebAuthn.RequireTrustedAttestation = "direct", true
	}), 200, "require trusted attestation")
	f.CreateUser("mdsuser")
	tok := f.AccountToken("mdsuser").Tokens.Str("access_token")
	opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
	key := newSoftKey("login.test", "https://login.test", false)
	key.aaguid, key.att = aaguidBytes(testAAGUID), vendor
	r := h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
		"credential": key.create(t, opts.Get("public_key")), "name": "key"})
	mustStatus(t, r, 201, "registration trusted through FIDO metadata")
	if r.Get("attestation_trusted") != true {
		t.Fatalf("credential: %s", r.Raw)
	}
	var source string
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT attestation_source FROM webauthn_credentials WHERE user_id=$1`, f.Users["mdsuser"]).Scan(&source)
	if source != "fido_metadata" {
		t.Fatalf("attestation source %q", source)
	}

	// A BLOB signed by another key does not load.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forgedBlob, forgedRoot := buildMDSBlob(t, testAAGUID, vendor.rootPEM, other)
	svc := passkey.New(h.App.D)
	if err := svc.LoadMetadata(configuration.WebAuthnConfig{MetadataFile: forgedBlob, MetadataRootFile: forgedRoot}); err == nil {
		t.Fatal("a metadata BLOB with a bad signature loaded")
	}
	// Without the private root, the FIDO production root does not accept it.
	if err := svc.LoadMetadata(configuration.WebAuthnConfig{MetadataFile: blob}); err == nil {
		t.Fatal("a test BLOB verified against the FIDO production root")
	}
}
