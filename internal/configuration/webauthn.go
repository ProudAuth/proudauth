package configuration

import "os"

// WebAuthnConfig holds the operator's passkey trust settings (PASS-009,
// PASS-010).
type WebAuthnConfig struct {
	// MetadataFile is a FIDO Metadata Service (MDS3) BLOB the operator
	// downloads and refreshes. It is verified against MetadataRootFile (the
	// FIDO Alliance production root when empty) and loaded at startup; its
	// entries are trusted metadata for realms that require trusted
	// attestation. The server never fetches metadata itself.
	MetadataFile string `yaml:"metadata_file"`
	// MetadataRootFile is a PEM root certificate for a private metadata
	// service.
	MetadataRootFile string `yaml:"metadata_root_file"`
	// RelatedOrigins lets realms declare WebAuthn Level 3 related origins
	// (PASS-010). Off by default: clients without Level 3 support refuse
	// such origins, so only turn it on for audiences whose browsers support
	// it.
	RelatedOrigins bool `yaml:"related_origins"`
}

func (w WebAuthnConfig) validate() []string {
	var errs []string
	for name, path := range map[string]string{"webauthn.metadata_file": w.MetadataFile, "webauthn.metadata_root_file": w.MetadataRootFile} {
		if path == "" {
			continue
		}
		if st, err := os.Stat(path); err != nil || st.IsDir() {
			errs = append(errs, name+" must name a readable file")
		}
	}
	if w.MetadataRootFile != "" && w.MetadataFile == "" {
		errs = append(errs, "webauthn.metadata_root_file needs webauthn.metadata_file")
	}
	return errs
}
