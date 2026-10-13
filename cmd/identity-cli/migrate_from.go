package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/proudbase/proudauth-sdk-go/admin"
	"github.com/proudbase/proudauth/internal/migrate"
)

// migrate-from converts a Keycloak, ZITADEL or SuperTokens export into
// ProudAuth import documents, reports what carries over (MIG-018) and, with
// --apply, submits them through the authenticated import APIs with the
// stored administrator session (identity-cli login).
func init() {
	register("migrate-from", "convert a keycloak|zitadel|supertokens export: plan with a capability report (default), or --apply through the import APIs", migrateFrom)
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func migrateFrom(args []string) error {
	source := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		source, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("migrate-from", flag.ContinueOnError)
	var inputs multiFlag
	fs.Var(&inputs, "input", "export file (repeatable; a Keycloak directory export has a realm file and users files)")
	realm := fs.String("realm", "main", "target realm")
	sourceSystem := fs.String("source-system", "", "source system name qualifying every source ID (default <source>-<realm or app>); keep it for the whole migration")
	sourceVersion := fs.String("source-version", "", "source product version, required when the export does not state it (ZITADEL, the SuperTokens core API list); "+
		"when the export states one, give that version or its major version (26 for 26.8.0)")
	mappingFile := fs.String("mapping", "", "reviewed organization and role translation (proudauth.migration-mapping.v1)")
	templateFile := fs.String("write-mapping-template", "", "write a mapping document with every organization and role key of the export, for review")
	plan := fs.Bool("plan", false, "dry run: convert, then validate through POST /user-imports with dry_run (the default)")
	apply := fs.Bool("apply", false, "create the organizations, import the users, then reconcile against the export's counts (fails when they do not match)")
	offline := fs.Bool("offline", false, "with --plan: only convert and report, without calling the server")
	reportFile := fs.String("report", "", "capability report file (default migration-report-<source system>.json)")
	docsDir := fs.String("write-documents", "", "also write the converted user-import documents to this directory (mode 0600; they contain password verifiers and TOTP seeds)")
	trust := fs.Bool("trust-email-verification", false, "keep the source's email verification flags (needs realm.users.verification.override)")
	reason := fs.String("verification-reason", "", "reason recorded for trusting the source's verification (10+ characters)")
	importTOTP := fs.Bool("import-totp", false, "carry compatible TOTP seeds over (needs realm.users.credentials.manage and an MFA session)")
	allowOwner := fs.Bool("allow-owner-roles", false, "allow memberships the mapping translates to an owner role")
	keepAttrs := fs.Bool("keep-attributes", false, "keep source attributes and metadata as administrator-only metadata")
	batch := fs.Int("batch-size", migrate.DefaultBatchSize, fmt.Sprintf("records per import job, 1 to %d (batches also stay below 192 KiB)", migrate.MaxBatchSize))
	printSQL := fs.Bool("print-export-sql", false, "print the read-only SuperTokens export query and exit")
	list := fs.Bool("list", false, "list the adapters with their supported and tested source versions and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if source == "" && fs.NArg() > 0 {
		source = fs.Arg(0)
	}
	switch {
	case *list:
		return printAdapters(os.Stdout)
	case *printSQL:
		if source != migrate.SuperTokens {
			return errors.New("--print-export-sql is for supertokens")
		}
		fmt.Print(migrate.SuperTokensExportSQL)
		return nil
	}
	if _, ok := migrate.LookupAdapter(source); !ok {
		return errors.New("usage: identity-cli migrate-from keycloak|zitadel|supertokens --input FILE [--mapping FILE] [--plan|--apply] (--list shows the adapters)")
	}
	if len(inputs) == 0 {
		return errors.New("--input is required")
	}
	if *plan && *apply {
		return errors.New("choose --plan or --apply")
	}
	if *offline && *apply {
		return errors.New("--offline only plans")
	}
	if *trust && len(strings.TrimSpace(*reason)) < 10 {
		return errors.New("--trust-email-verification needs --verification-reason (10+ characters)")
	}
	if migrate.CheckBatchSize(*batch) != nil {
		return fmt.Errorf("--batch-size %d is out of range: it must be between 1 and %d records per import job", *batch, migrate.MaxBatchSize)
	}
	docs := make([][]byte, 0, len(inputs))
	for _, in := range inputs {
		b, err := os.ReadFile(in)
		if err != nil {
			return err
		}
		docs = append(docs, b)
	}
	var mapping *migrate.Mapping
	if *mappingFile != "" {
		b, err := os.ReadFile(*mappingFile)
		if err != nil {
			return err
		}
		if mapping, err = migrate.ParseMapping(b); err != nil {
			return err
		}
	}
	res, err := migrate.Convert(source, docs, migrate.Options{SourceSystem: *sourceSystem, SourceVersion: *sourceVersion, Mapping: mapping,
		KeepAttributes: *keepAttrs, ImportTOTP: *importTOTP})
	if err != nil {
		return err
	}
	if *templateFile != "" {
		b, _ := json.MarshalIndent(migrate.Template(res, mapping), "", "  ")
		if err := writePrivateFile(*templateFile, append(b, '\n')); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "wrote mapping template", *templateFile, "- review every entry before using it with --mapping")
	}
	if *docsDir != "" {
		if err := writeImportDocuments(*docsDir, res, *batch); err != nil {
			return err
		}
	}
	var applyErr error
	if !*offline {
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		ap := &migrate.Applier{Call: sdkCaller(c), BatchSize: *batch, Log: func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }}
		_, applyErr = ap.Apply(context.Background(), res, migrate.ApplyOptions{DryRun: !*apply, TrustEmailVerification: *trust,
			VerificationReason: *reason, AllowOwnerRoles: *allowOwner, ImportTOTP: *importTOTP})
	}
	out := *reportFile
	if out == "" {
		out = "migration-report-" + res.SourceSystem + ".json"
	}
	b, _ := json.MarshalIndent(res.Report, "", "  ")
	if err := writePrivateFile(out, append(b, '\n')); err != nil {
		return err
	}
	printReport(os.Stdout, res.Report)
	fmt.Fprintln(os.Stderr, "capability report written to", out)
	return applyErr
}

// sdkCaller adapts the administration client to the migration applier.
func sdkCaller(c *admin.Client) migrate.Caller {
	return func(ctx context.Context, method, path string, body, out any, key string) error {
		var opts []admin.RequestOption
		if key != "" {
			opts = append(opts, admin.WithIdempotencyKey(key))
		}
		_, err := c.Do(ctx, method, path, body, out, opts...)
		var p *admin.Problem
		if errors.As(err, &p) {
			return &migrate.APIError{Status: p.Status, Detail: p.Error()}
		}
		return err
	}
}

// writeImportDocuments writes the user-import request bodies, for review or
// for submitting another way. They carry password verifiers and TOTP seeds.
func writeImportDocuments(dir string, res *migrate.Result, size int) error {
	if err := migrate.CheckBatchSize(size); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	orgs, _ := json.MarshalIndent(res.Organizations, "", "  ")
	if err := writePrivateFile(filepath.Join(dir, "organizations.json"), orgs); err != nil {
		return err
	}
	for i := 0; i*size < len(res.Users); i++ {
		end := min((i+1)*size, len(res.Users))
		b, _ := json.MarshalIndent(map[string]any{"format": "proudauth.user-import.v1", "source_system": res.SourceSystem, "users": res.Users[i*size : end]}, "", "  ")
		if err := writePrivateFile(filepath.Join(dir, fmt.Sprintf("user-import-%03d.json", i+1)), b); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "wrote import documents to", dir, "(they contain password verifiers: delete them after the migration)")
	return nil
}

func printAdapters(w io.Writer) error {
	for _, a := range migrate.Adapters {
		fmt.Fprintf(w, "%s (%s)\n  supported: %s; tested: %s\n  export: %s\n  how: %s\n", a.Source, a.Product, a.SupportedVersions,
			strings.Join(a.TestedVersions, ", "), a.ExportFormat, a.ExportCommand)
		fmt.Fprintf(w, "  converts: %s\n  with loss: %s\n  unsupported: %s\n\n", strings.Join(a.Converts, "; "),
			strings.Join(a.ConvertsWithLoss, "; "), strings.Join(a.Unsupported, "; "))
	}
	return nil
}

func printReport(w io.Writer, r *migrate.Report) {
	s := r.Summary
	fmt.Fprintf(w, "%s %s -> source system %s\n", r.Source.Product, r.Source.Version, r.SourceSystem)
	fmt.Fprintf(w, "users %d (to import %d), passwords migrated %d, password resets required %d, TOTP migrated %d, MFA re-enrollments %d, suspended %d\n",
		s.Users, s.UsersToImport, s.PasswordsMigrated, s.PasswordResetsRequired, s.TOTPMigrated, s.MFAReenrollmentsRequired, s.SuspendedAccounts)
	fmt.Fprintf(w, "organizations %d, memberships %d, role assignments %d, untranslated role grants %d\n\n", s.Organizations, s.Memberships,
		s.RoleAssignments, s.UntranslatedRoleGrants)
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ENTITY\tTOTAL\tCONVERTED\tWITH LOSS\tUNSUPPORTED\tIGNORED")
	names := make([]string, 0, len(r.Entities))
	for n := range r.Entities {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e := r.Entities[n]
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\n", n, e.Total, e.Converted, e.ConvertedWithLoss, e.Unsupported, e.Ignored)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	for _, n := range names {
		for _, rc := range r.Entities[n].Reasons {
			if rc.Outcome == migrate.Unsupported {
				fmt.Fprintf(w, "unsupported %s (%d): %s\n", n, rc.Count, rc.Reason)
			}
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintln(w, "note:", n)
	}
	if im := r.Import; im != nil {
		mode := "import"
		if im.DryRun {
			mode = "dry run"
		}
		fmt.Fprintf(w, "\n%s: jobs %s; counts %v; totals %v\n", mode, strings.Join(im.Jobs, ", "), im.Counts, im.Totals)
		for _, o := range im.Organizations {
			fmt.Fprintf(w, "organization %s: %s %s %s\n", o.Slug, o.Status, o.ID, o.Detail)
		}
		for _, rec := range im.Records {
			fmt.Fprintf(w, "record %s: %s %s\n", rec.SourceID, rec.Status, rec.Error)
		}
		if rec := im.Reconciliation; rec != nil {
			fmt.Fprintf(w, "reconciliation: reconciled %v; expected %v; users %v, credentials %v\n", rec["reconciled"], im.Expected, rec["users"], rec["credentials"])
			ms, _ := rec["mismatches"].([]any)
			for _, m := range ms {
				if mm, ok := m.(map[string]any); ok {
					fmt.Fprintf(w, "reconciliation mismatch %v: expected %v, actual %v\n", mm["measure"], mm["expected"], mm["actual"])
				}
			}
		} else if im.Expected != nil {
			fmt.Fprintf(w, "reconciliation: failed (expected %v)\n", im.Expected)
		}
	}
}
