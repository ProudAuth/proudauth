// Package plugin manages plugin packages (EXT-014): signed, versioned
// bundles of extension configuration (pre-action hooks, webhook
// subscriptions, lifecycle workflows) with a manifest that declares the
// permissions the bundle needs, the contract versions it requires and the
// plugins it depends on.
//
// A plugin never runs code inside the server: everything it configures
// already runs out of process (hooks and webhooks are HTTPS endpoints behind
// the egress policy) or as bounded workflow steps (EXT-013). Installing a
// plugin is therefore exactly as powerful as configuring its parts through
// the administration API, and goes through the same validation and the same
// authority checks:
//   - the package must be signed (Ed25519) by a publisher key the operator
//     trusts in configuration; there is no unsigned mode;
//   - every part is validated with the API's own validation at upload and
//     again at installation;
//   - the manifest must declare every permission its parts need, and the
//     uploader, the reviewer and the installer must each hold all of them;
//   - a second administrator approves each version unless the realm policy
//     explicitly allows single-administrator installs;
//   - disabling stops every part in one transaction; upgrades keep the
//     previous version so it can be rolled back without a new review.
package plugin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/contracts"
	"github.com/proudbase/proudauth/internal/hooks"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/webhooks"
)

// SigningContext prefixes the signed bytes, so a plugin signature can never
// be replayed as a signature over anything else (domain separation).
const SigningContext = "proudauth-plugin-v1\n"

// Limits (NFR-001).
const (
	MaxManifestBytes = 16 << 10
	MaxPayloadBytes  = 160 << 10
	MaxParts         = 20
	MaxDependencies  = 10
)

// Package is the upload format. Manifest and payload travel as base64 of
// their exact bytes, so the signature survives any JSON tooling in between.
type Package struct {
	Manifest  string    `json:"manifest"`
	Payload   string    `json:"payload"`
	Signature Signature `json:"signature"`
}

// Signature is the publisher's signature over SigningContext + manifest
// bytes. The manifest binds the payload by its SHA-256 digest.
type Signature struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Manifest describes a plugin version (manifest_version 1,
// api/plugins/manifest.v1.json).
type Manifest struct {
	ManifestVersion int    `json:"manifest_version"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Publisher       string `json:"publisher"`
	Description     string `json:"description,omitempty"`
	// Permissions are the capabilities the plugin's parts need; nothing it
	// configures may need more.
	Permissions []string `json:"permissions"`
	// Requires lists, per contract, the versions the plugin works with; the
	// server must support at least one of each.
	Requires     map[string][]int `json:"requires,omitempty"`
	Dependencies []Dependency     `json:"dependencies,omitempty"`
	// PayloadSHA256 is the hex SHA-256 of the payload bytes.
	PayloadSHA256 string `json:"payload_sha256"`
}

// Dependency is another plugin that must be installed and enabled.
type Dependency struct {
	Name       string `json:"name"`
	MinVersion string `json:"min_version"`
}

// Payload is the configuration a plugin installs.
type Payload struct {
	Hooks     []hooks.Input    `json:"hooks,omitempty"`
	Webhooks  []webhooks.Input `json:"webhooks,omitempty"`
	Workflows []WorkflowPart   `json:"workflows,omitempty"`
}

// WorkflowPart is a lifecycle workflow a plugin installs.
type WorkflowPart struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Definition  json.RawMessage `json:"definition"`
}

var (
	pluginName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	semverRe   = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
)

// Semver is a parsed MAJOR.MINOR.PATCH version.
type Semver [3]int

// ParseSemver parses a strict MAJOR.MINOR.PATCH version.
func ParseSemver(v string) (Semver, bool) {
	m := semverRe.FindStringSubmatch(v)
	if m == nil {
		return Semver{}, false
	}
	var s Semver
	for i := 0; i < 3; i++ {
		s[i], _ = strconv.Atoi(m[i+1])
	}
	return s, true
}

// Less reports a < b.
func (a Semver) Less(b Semver) bool {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// Verified is a package whose signature, digest and manifest checked out.
type Verified struct {
	Manifest    Manifest
	Payload     Payload
	ManifestRaw []byte
	PayloadRaw  []byte
	Digest      string
	KeyID       string
	Signature   string
}

func strict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func invalid(field, msg string) error { return problem.ErrValidation.WithField(field, msg) }

// Verify checks a package's signature against the trusted publisher keys,
// the payload digest and the manifest's structure. It does not consult the
// realm (see Service.check).
func Verify(pkg Package, trusted []configuration.PluginPublisherKey, now time.Time) (*Verified, error) {
	manifestRaw, err := base64.StdEncoding.DecodeString(pkg.Manifest)
	if err != nil || len(manifestRaw) == 0 || len(manifestRaw) > MaxManifestBytes {
		return nil, invalid("manifest", "base64 of a manifest of at most 16 KiB")
	}
	payloadRaw, err := base64.StdEncoding.DecodeString(pkg.Payload)
	if err != nil || len(payloadRaw) == 0 || len(payloadRaw) > MaxPayloadBytes {
		return nil, invalid("payload", "base64 of a payload of at most 160 KiB")
	}
	if pkg.Signature.Algorithm != "Ed25519" {
		return nil, invalid("signature.algorithm", "Ed25519")
	}
	var key *configuration.PluginPublisherKey
	for i := range trusted {
		if trusted[i].KeyID == pkg.Signature.KeyID {
			key = &trusted[i]
		}
	}
	if key == nil {
		return nil, problem.ErrForbidden.WithDetail("the package is not signed by a publisher key this deployment trusts")
	}
	if key.NotAfter != "" {
		if t, err := time.Parse(time.RFC3339, key.NotAfter); err != nil || !now.Before(t) {
			return nil, problem.ErrForbidden.WithDetail("the publisher key has expired")
		}
	}
	pub, err := key.Ed25519()
	if err != nil {
		return nil, problem.ErrForbidden.WithDetail("the publisher key is unusable")
	}
	sig, err := base64.StdEncoding.DecodeString(pkg.Signature.Value)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, append([]byte(SigningContext), manifestRaw...), sig) {
		return nil, problem.ErrForbidden.WithDetail("the package signature does not verify")
	}
	var probe struct {
		ManifestVersion int `json:"manifest_version"`
	}
	if err := json.Unmarshal(manifestRaw, &probe); err != nil {
		return nil, invalid("manifest", "must be a JSON object")
	}
	if !contracts.IsSupported(contracts.PluginManifest, probe.ManifestVersion) {
		return nil, invalid("manifest.manifest_version", "supported manifest versions: "+contracts.SupportedList(contracts.PluginManifest))
	}
	var m Manifest
	if err := strict(manifestRaw, &m); err != nil {
		return nil, invalid("manifest", "invalid manifest: "+trimDecodeErr(err))
	}
	if m.Publisher != key.Publisher {
		return nil, problem.ErrForbidden.WithDetail("the manifest's publisher does not match the signing key's publisher")
	}
	sum := sha256.Sum256(payloadRaw)
	if !strings.EqualFold(m.PayloadSHA256, hex.EncodeToString(sum[:])) {
		return nil, problem.ErrForbidden.WithDetail("the payload does not match the signed digest")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	var p Payload
	if err := strict(payloadRaw, &p); err != nil {
		return nil, invalid("payload", "invalid payload: "+trimDecodeErr(err))
	}
	if len(p.Hooks)+len(p.Webhooks)+len(p.Workflows) == 0 {
		return nil, invalid("payload", "a plugin configures at least one part")
	}
	if len(p.Hooks) > MaxParts || len(p.Webhooks) > MaxParts || len(p.Workflows) > MaxParts {
		return nil, invalid("payload", fmt.Sprintf("at most %d parts of each kind", MaxParts))
	}
	digest := sha256.Sum256(append(append(append([]byte{}, manifestRaw...), 0), payloadRaw...))
	return &Verified{Manifest: m, Payload: p, ManifestRaw: manifestRaw, PayloadRaw: payloadRaw, Digest: hex.EncodeToString(digest[:]),
		KeyID: key.KeyID, Signature: pkg.Signature.Value}, nil
}

func trimDecodeErr(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "unknown field"); i >= 0 {
		return msg[i:]
	}
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

func (m *Manifest) validate() error {
	if !pluginName.MatchString(m.Name) {
		return invalid("manifest.name", "2..63 characters a-z, 0-9 or -")
	}
	if _, ok := ParseSemver(m.Version); !ok {
		return invalid("manifest.version", "MAJOR.MINOR.PATCH")
	}
	if len(m.Description) > 500 {
		return invalid("manifest.description", "at most 500 characters")
	}
	if len(m.Permissions) == 0 || len(m.Permissions) > 50 {
		return invalid("manifest.permissions", "1..50 permissions")
	}
	for _, p := range m.Permissions {
		if authorization.PermissionSensitivity(p) == "" {
			return invalid("manifest.permissions", "unknown permission "+p)
		}
	}
	for name, versions := range m.Requires {
		if _, ok := contracts.Lookup(name); !ok {
			return problem.ErrValidation.WithField("manifest.requires", "this server does not know the contract "+name+"; upgrade the server").
				WithExtension("incompatible", true)
		}
		ok := false
		for _, v := range versions {
			ok = ok || contracts.IsSupported(name, v)
		}
		if !ok {
			return problem.ErrValidation.WithField("manifest.requires."+name, "this server supports "+contracts.SupportedList(name)).
				WithExtension("incompatible", true)
		}
	}
	if len(m.Dependencies) > MaxDependencies {
		return invalid("manifest.dependencies", fmt.Sprintf("at most %d", MaxDependencies))
	}
	for i, d := range m.Dependencies {
		if !pluginName.MatchString(d.Name) || d.Name == m.Name {
			return invalid(fmt.Sprintf("manifest.dependencies[%d].name", i), "another plugin's name")
		}
		if _, ok := ParseSemver(d.MinVersion); !ok {
			return invalid(fmt.Sprintf("manifest.dependencies[%d].min_version", i), "MAJOR.MINOR.PATCH")
		}
	}
	return nil
}

// requiredPermissions derives what the payload's parts need.
func requiredPermissions(p Payload, workflowPerms func(WorkflowPart) ([]string, error)) ([]string, error) {
	var out []string
	add := func(perms ...string) {
		for _, x := range perms {
			if !slices.Contains(out, x) {
				out = append(out, x)
			}
		}
	}
	if len(p.Hooks) > 0 {
		add("realm.hooks.write")
	}
	if len(p.Webhooks) > 0 {
		add("realm.webhooks.write")
	}
	for _, w := range p.Workflows {
		perms, err := workflowPerms(w)
		if err != nil {
			return nil, err
		}
		add(perms...)
	}
	slices.Sort(out)
	return out, nil
}
