package storage

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// lintBase creates the tables, the schema and the type the lint cases act
// on, as an earlier migration would.
const lintBase = `CREATE TABLE t (id int PRIMARY KEY, a int, b text, c text);
CREATE TABLE "Audit" (id int);
CREATE SCHEMA s;
CREATE TABLE s.u (id int);
CREATE TYPE mood AS ENUM ('a');
`

// lintCase lints lintBase as 0001_base.sql and body as 0002_case.sql and
// returns the findings of 0002_case.sql as "rule subject".
func lintCase(t *testing.T, body string) ([]string, []LintFinding) {
	t.Helper()
	findings, err := lintMigrationFiles(fstest.MapFS{
		"0001_base.sql": &fstest.MapFile{Data: []byte(lintBase)},
		"0002_case.sql": &fstest.MapFile{Data: []byte(body)},
		"README.md":     &fstest.MapFile{Data: []byte("DROP TABLE t;")},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	var of []LintFinding
	for _, f := range findings {
		if f.File != "0002_case.sql" {
			t.Fatalf("finding in the base file: %s", f)
		}
		got = append(got, f.Rule+" "+f.Subject)
		of = append(of, f)
	}
	return got, of
}

// TestLintMigrationRules covers the migration lint (OPS-008, DEP-012,
// TEST-061): every rule reports its DDL on a table that already exists, in
// the forms PostgreSQL accepts (schema-qualified and quoted names, IF [NOT]
// EXISTS, ONLY, several actions in one ALTER TABLE, DO blocks), and stays
// quiet on the safe forms: an index on a table the same file creates,
// CONCURRENTLY in a no-transaction file, constant defaults, and destructive
// DDL in a file marked compat=contract or reviewed-expand with a reason.
// Each rule has a case that fails when the rule is removed.
func TestLintMigrationRules(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		// blocking-index
		{"plain index on an existing table", "CREATE INDEX t_a ON t (a);", []string{"blocking-index t_a"}},
		{"unique index, IF NOT EXISTS, ONLY and a schema", "CREATE UNIQUE INDEX IF NOT EXISTS u_id ON ONLY s.u (id);", []string{"blocking-index u_id"}},
		{"unnamed index names its table", "CREATE INDEX ON public.t USING btree (b);", []string{"blocking-index t"}},
		{"index on a table created in the same file", "CREATE TABLE IF NOT EXISTS n (id int);\nCREATE INDEX n_id ON public.n (id);\nCREATE UNIQUE INDEX ON \"n\" (id);", nil},
		{"quoted names keep their case", "CREATE TABLE \"N\" (id int);\nCREATE INDEX n_id ON N (id);", []string{"blocking-index n_id"}},
		{"CREATE TABLE IF NOT EXISTS of an existing table creates nothing", "CREATE TABLE IF NOT EXISTS t (id int);\nCREATE INDEX t_b ON t (b);", []string{"blocking-index t_b"}},
		{"ADD UNIQUE builds an index", "ALTER TABLE t ADD CONSTRAINT t_b_key UNIQUE (b), ADD PRIMARY KEY (id);", []string{"blocking-index t.t_b_key", "blocking-index t"}},
		{"ADD UNIQUE USING INDEX adopts a built one", "ALTER TABLE t ADD CONSTRAINT t_b_key UNIQUE USING INDEX t_b_idx, ADD CONSTRAINT t_pk PRIMARY KEY USING INDEX t_id_idx;", nil},
		{"ADD COLUMN UNIQUE builds an index", "ALTER TABLE t ADD COLUMN d text UNIQUE;", []string{"blocking-index t.d"}},
		{"allowed with a reason", "-- proudauth:allow-blocking-index: t is written only by the migration itself\nCREATE INDEX t_a ON t (a);", nil},
		{"allow needs a reason", "-- proudauth:allow-blocking-index:\nCREATE INDEX t_a ON t (a);", []string{"blocking-index t_a"}},

		// concurrently-in-transaction
		{"CONCURRENTLY in a no-transaction file", "-- proudauth:no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS t_c ON t (c);\nREINDEX INDEX CONCURRENTLY t_c;", nil},
		{"CONCURRENTLY in a transaction", "CREATE INDEX CONCURRENTLY IF NOT EXISTS t_c ON t (c);", []string{"concurrently-in-transaction t_c"}},
		{"DROP INDEX CONCURRENTLY in a contract file", "-- proudauth:compat=contract\nDROP INDEX CONCURRENTLY IF EXISTS t_old;", []string{"concurrently-in-transaction t_old"}},

		// table-rewrite and column-type
		{"column type", "ALTER TABLE t ALTER COLUMN a TYPE bigint;", []string{"table-rewrite t.a", "column-type t.a"}},
		{"SET DATA TYPE without COLUMN", "ALTER TABLE IF EXISTS ONLY t ALTER a SET DATA TYPE numeric(10, 2) USING a::numeric(10, 2);", []string{"table-rewrite t.a", "column-type t.a"}},
		{"contract allows the type change, not the rewrite", "-- proudauth:compat=contract\nALTER TABLE t ALTER COLUMN a TYPE bigint;", []string{"table-rewrite t.a"}},
		{"allow-table-rewrite allows the rewrite, not the type change", "-- proudauth:allow-table-rewrite: t holds a few rows\nALTER TABLE t ALTER COLUMN a TYPE bigint;", []string{"column-type t.a"}},
		{"stored generated column", "ALTER TABLE t ADD COLUMN g int GENERATED ALWAYS AS (a * 2) STORED;", []string{"table-rewrite t.g"}},
		{"virtual generated column", "ALTER TABLE t ADD COLUMN g int GENERATED ALWAYS AS (a * 2) VIRTUAL;", nil},

		// volatile-default
		{"DEFAULT now()", "ALTER TABLE t ADD COLUMN d timestamptz NOT NULL DEFAULT now();", []string{"volatile-default t.d"}},
		{"constant defaults", "ALTER TABLE t ADD COLUMN d text NOT NULL DEFAULT 'x', ADD COLUMN e jsonb NOT NULL DEFAULT '{}'::jsonb, " +
			"ADD COLUMN IF NOT EXISTS f integer NOT NULL DEFAULT 0 CHECK (f >= 0), ADD g character varying(10) DEFAULT 'a'::character varying(10), " +
			"ADD h jsonb DEFAULT jsonb_build_object('k', 1), ADD i interval DEFAULT interval '1 day', ADD j text[] DEFAULT ARRAY['a', 'b'] REFERENCES x (id), " +
			"ADD k boolean DEFAULT NULL, ADD l numeric DEFAULT CAST(-1.5 AS numeric(4, 1)), ADD m text DEFAULT 'oidc' CHECK (m IN ('oidc', 'saml'));", nil},
		{"volatile and stable defaults", "ALTER TABLE t ADD d timestamptz DEFAULT CURRENT_TIMESTAMP, ADD e uuid DEFAULT gen_random_uuid(), " +
			"ADD f timestamptz DEFAULT pg_catalog.clock_timestamp(), ADD g bigint DEFAULT nextval('t_seq'::regclass), ADD h text DEFAULT ('x' || random()::text);",
			[]string{"volatile-default t.d", "volatile-default t.e", "volatile-default t.f", "volatile-default t.g", "volatile-default t.h"}},
		{"serial and identity columns", "ALTER TABLE t ADD COLUMN s bigserial, ADD COLUMN i int GENERATED ALWAYS AS IDENTITY;", []string{"volatile-default t.s", "volatile-default t.i"}},
		{"defaults and drops on a table created in the same file", "CREATE TABLE n (id int);\nALTER TABLE n ADD COLUMN d timestamptz DEFAULT now(), DROP COLUMN id;\nDROP TABLE n;", nil},

		// compatibility rules
		{"DROP TABLE", "DROP TABLE IF EXISTS t, s.u CASCADE;", []string{"drop-table t", "drop-table s.u"}},
		{"DROP COLUMN among other actions", "ALTER TABLE ONLY t ADD COLUMN z int, DROP COLUMN IF EXISTS b, DROP c CASCADE;", []string{"drop-column t.b", "drop-column t.c"}},
		{"DROP INDEX", "DROP INDEX t_old;", []string{"drop-index t_old"}},
		{"DROP CONSTRAINT", "ALTER TABLE t DROP CONSTRAINT IF EXISTS t_a_check;", []string{"drop-constraint t.t_a_check"}},
		{"NOT NULL and defaults", "ALTER TABLE t ALTER COLUMN a DROP NOT NULL, ALTER b SET NOT NULL, ALTER COLUMN c DROP DEFAULT;",
			[]string{"drop-not-null t.a", "set-not-null t.b", "drop-default t.c"}},
		{"RENAME and SET SCHEMA", "ALTER TABLE t RENAME COLUMN a TO a2;\nALTER TABLE t RENAME b TO b2;\nALTER TABLE t RENAME CONSTRAINT t_pkey TO t_pk;\n" +
			"ALTER TABLE \"Audit\" RENAME TO audit;\nALTER INDEX IF EXISTS t_a RENAME TO t_a2;\nALTER TABLE s.u SET SCHEMA public;",
			[]string{"rename t.a", "rename t.b", "rename t.t_pkey", "rename Audit", "rename t_a", "rename s.u"}},
		{"ALTER TYPE and ALTER DOMAIN", "ALTER TYPE mood ADD VALUE 'b';\nALTER DOMAIN email_address SET NOT NULL;", []string{"alter-type mood", "alter-type email_address"}},
		{"TRUNCATE", "TRUNCATE TABLE ONLY t, s.u RESTART IDENTITY;", []string{"truncate t", "truncate s.u"}},
		{"other DROPs", "DROP VIEW IF EXISTS v;\nDROP MATERIALIZED VIEW mv;\nDROP FUNCTION f(int);", []string{"drop-object v", "drop-object mv", "drop-object f"}},
		{"compat=contract allows destructive DDL", "-- proudauth:compat=contract\nDROP INDEX t_old;\nALTER TABLE t DROP COLUMN b, ALTER c SET NOT NULL;", nil},
		{"reviewed-expand with a reason allows destructive DDL", "-- proudauth:reviewed-expand: no released binary uses t_old\nDROP INDEX t_old;", nil},
		{"reviewed-expand needs a reason", "-- proudauth:reviewed-expand:\nDROP INDEX t_old;", []string{"drop-index t_old"}},
		{"reviewed-expand does not allow lock rules", "-- proudauth:reviewed-expand: older binaries ignore d\nALTER TABLE t ADD d timestamptz DEFAULT now();", []string{"volatile-default t.d"}},

		// what the lint reads and what it does not
		{"comments and strings are not statements", "-- DROP TABLE t;\n/* ALTER TABLE t DROP COLUMN a; /* nested */ */\n" +
			"INSERT INTO t (b) VALUES ('DROP TABLE t; ALTER TABLE t DROP COLUMN a');\nCOMMENT ON TABLE t IS 'CREATE INDEX x ON t (a)';\nSELECT $q$TRUNCATE t$q$;", nil},
		{"DO block statements", "DO $$\nBEGIN\n  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 't_b') THEN\n    CREATE INDEX t_b ON t (b);\n  END IF;\n" +
			"  ALTER TABLE t DROP COLUMN c;\n  EXECUTE 'DROP TABLE s.u';\nEND\n$$;", []string{"blocking-index t_b", "drop-column t.c", "drop-table s.u"}},
		{"function bodies run only when called", "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN DROP TABLE t; END $$;", nil},
		{"unreadable file", "SELECT 'unterminated;", []string{"unreadable -"}},
	} {
		got, _ := lintCase(t, tc.body)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestLintFindingText covers the lint's report (OPS-008): a finding names
// the line of its statement and says how to fix or allow it.
func TestLintFindingText(t *testing.T) {
	_, f := lintCase(t, "-- header\n\nALTER TABLE t ADD COLUMN d text;\n/* a comment */ CREATE INDEX t_d\n  ON t (d);\nDROP INDEX t_old;\n")
	if len(f) != 2 || f[0].Line != 4 || f[1].Line != 6 {
		t.Fatalf("findings %v", f)
	}
	for _, want := range []string{"0002_case.sql:4: blocking-index t_d:", "CREATE INDEX CONCURRENTLY", noTransactionDirective, "-- proudauth:allow-blocking-index: <reason>"} {
		if !strings.Contains(f[0].String(), want) {
			t.Errorf("%q does not say %q", f[0], want)
		}
	}
	for _, want := range []string{contractMarker, reviewedExpandMarker} {
		if !strings.Contains(f[1].Message, want) {
			t.Errorf("%q does not say %q", f[1], want)
		}
	}
}

// TestLintBaseline covers the baseline of historical findings (OPS-008,
// TEST-061): it is exact. Each entry explains one finding, a finding
// without an entry is unexplained and an entry without a finding is stale.
func TestLintBaseline(t *testing.T) {
	baseline, err := ParseLintBaseline("# history\n\n0001_a.sql blocking-index ix_a  built while empty\n0001_a.sql blocking-index ix_a second build\n0002_b.sql drop-index ix_b replaced\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []LintBaselineEntry{
		{File: "0001_a.sql", Rule: "blocking-index", Subject: "ix_a", Reason: "built while empty", Line: 3},
		{File: "0001_a.sql", Rule: "blocking-index", Subject: "ix_a", Reason: "second build", Line: 4},
		{File: "0002_b.sql", Rule: "drop-index", Subject: "ix_b", Reason: "replaced", Line: 5},
	}
	if !reflect.DeepEqual(baseline, want) {
		t.Fatalf("parsed %+v", baseline)
	}
	if _, err := ParseLintBaseline("0001_a.sql blocking-index ix_a\n"); err == nil {
		t.Fatal("an entry without a reason was accepted")
	}

	a := LintFinding{File: "0001_a.sql", Rule: "blocking-index", Subject: "ix_a"}
	b := LintFinding{File: "0002_b.sql", Rule: "drop-index", Subject: "ix_b"}
	c := LintFinding{File: "0002_b.sql", Rule: "drop-index", Subject: "ix_c"}
	if u, s := applyLintBaseline([]LintFinding{a, a, b}, baseline); len(u) != 0 || len(s) != 0 {
		t.Fatalf("exact baseline: unexplained %v, stale %v", u, s)
	}
	if u, s := applyLintBaseline([]LintFinding{a, a, b, c}, baseline); !reflect.DeepEqual(u, []LintFinding{c}) || len(s) != 0 {
		t.Fatalf("new finding: unexplained %v, stale %v", u, s)
	}
	if u, s := applyLintBaseline([]LintFinding{a, a, b}, baseline[1:]); !reflect.DeepEqual(u, []LintFinding{a}) || len(s) != 0 {
		t.Fatalf("removed entry: unexplained %v, stale %v", u, s)
	}
	if u, s := applyLintBaseline([]LintFinding{a, b}, baseline); len(u) != 0 || !reflect.DeepEqual(s, baseline[1:2]) {
		t.Fatalf("entry without a finding: unexplained %v, stale %v", u, s)
	}
}
