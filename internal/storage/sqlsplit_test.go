package storage

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestSplitSQL covers the statement splitter of no-transaction migrations
// (OPS-008): semicolons split statements only outside string literals,
// quoted identifiers, comments, dollar quotes and parentheses, and anything
// it cannot tokenize with certainty is refused.
func TestSplitSQL(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      []string
	}{
		{"plain", "SELECT 1; SELECT 2;", []string{"SELECT 1", "SELECT 2"}},
		{"no final semicolon", "SELECT 1;\nSELECT 2\n", []string{"SELECT 1", "SELECT 2"}},
		{"string with doubled quote", "SELECT 'a;''b'; SELECT 2", []string{"SELECT 'a;''b'", "SELECT 2"}},
		{"standard string keeps backslash", `SELECT 'a\'; SELECT 2`, []string{`SELECT 'a\'`, "SELECT 2"}},
		{"escape string", `SELECT E'a\';b'; SELECT e'\\'; SELECT 3`, []string{`SELECT E'a\';b'`, `SELECT e'\\'`, "SELECT 3"}},
		{"prefixed strings", `SELECT B'1;', X'0;', N'n;', U&'d\0061;'; SELECT 2`, []string{`SELECT B'1;', X'0;', N'n;', U&'d\0061;'`, "SELECT 2"}},
		{"quoted identifier", `CREATE TABLE "a;""b" (id int); SELECT 1`, []string{`CREATE TABLE "a;""b" (id int)`, "SELECT 1"}},
		{"line comment", "SELECT 1 -- not; here\n; SELECT 2", []string{"SELECT 1 -- not; here", "SELECT 2"}},
		{"nested block comment", "/* a /* ; */ ; */ SELECT 1; SELECT 2", []string{"/* a /* ; */ ; */ SELECT 1", "SELECT 2"}},
		{"dollar quoting", "DO $$ BEGIN PERFORM 1; END $$; DO $fn$ SELECT '$$'; $fn$; SELECT 3",
			[]string{"DO $$ BEGIN PERFORM 1; END $$", "DO $fn$ SELECT '$$'; $fn$", "SELECT 3"}},
		{"dollar tag inside a word and parameters", "SELECT a$b, $1; SELECT 2", []string{"SELECT a$b, $1", "SELECT 2"}},
		{"parentheses", "CREATE RULE r AS ON INSERT TO t DO ALSO (SELECT 1; SELECT 2); SELECT 3",
			[]string{"CREATE RULE r AS ON INSERT TO t DO ALSO (SELECT 1; SELECT 2)", "SELECT 3"}},
		{"comment-only statements dropped", "-- header\n;\n/* only */;\nSELECT 1.5e-3;\n-- trailer\n", []string{"SELECT 1.5e-3"}},
	} {
		got, err := splitSQL(tc.src)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		var sqls []string
		for _, s := range got {
			sqls = append(sqls, s.SQL)
		}
		if !reflect.DeepEqual(sqls, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, sqls, tc.want)
		}
	}
	for name, src := range map[string]string{
		"unterminated string":        "SELECT 'a; SELECT 2",
		"unterminated escape string": `SELECT E'a\'; SELECT 2`,
		"unterminated identifier":    `SELECT "a; SELECT 2`,
		"empty identifier":           `SELECT ""`,
		"unterminated comment":       "/* a /* b */ SELECT 1;",
		"unterminated dollar quote":  "DO $x$ BEGIN END $y$;",
		"stray dollar":               "SELECT $ 1;",
		"psql meta-command":          "\\connect other\nSELECT 1;",
		"unclosed parenthesis":       "SELECT (1; SELECT 2;",
		"extra parenthesis":          "SELECT 1); SELECT 2;",
	} {
		if got, err := splitSQL(src); err == nil {
			t.Errorf("%s: accepted as %d statements", name, len(got))
		}
	}
}

// TestParseNoTransaction covers the rules of a no-transaction migration
// (OPS-008, DEP-012): every CREATE INDEX and DROP INDEX is repeatable, the
// indexes it creates are named for the validity check, its concurrent
// statements are marked, and transaction control and BEGIN ATOMIC bodies
// are refused.
func TestParseNoTransaction(t *testing.T) {
	stmts, err := parseNoTransaction("-- proudauth:no-transaction\n" +
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_a ON public.t (a);\n" +
		"create unique index concurrently if not exists \"Ix\"\"B\" on only \"S\".\"T\" USING btree (lower(b)) WHERE (c IS NULL);\n" +
		"CREATE INDEX IF NOT EXISTS IX_C ON T (a);\n" +
		"DROP INDEX CONCURRENTLY IF EXISTS ix_old;\n" +
		"ALTER TABLE t ADD COLUMN IF NOT EXISTS d text;\n")
	if err != nil {
		t.Fatal(err)
	}
	var got []indexDDL
	var concurrently []bool
	for _, s := range stmts {
		if s.Index != nil {
			got = append(got, *s.Index)
		}
		concurrently = append(concurrently, s.Concurrently)
	}
	want := []indexDDL{
		{Name: "ix_a", Table: "public.t", Concurrently: true},
		{Name: `Ix"B`, Table: `"S"."T"`, Concurrently: true},
		{Name: "ix_c", Table: "T"},
	}
	if len(stmts) != 5 || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %d statements, indexes %+v", len(stmts), got)
	}
	// CREATE INDEX CONCURRENTLY and DROP INDEX CONCURRENTLY run without
	// lock_timeout; everything else keeps it.
	if want := []bool{true, true, false, true, false}; !reflect.DeepEqual(concurrently, want) {
		t.Fatalf("concurrent statements %v, want %v", concurrently, want)
	}
	if !strings.HasPrefix(stmts[0].SQL, "-- proudauth:no-transaction\nCREATE INDEX") {
		t.Fatalf("statement text: %q", stmts[0].SQL)
	}
	for name, tc := range map[string]struct {
		src string
		// rule: refused by a no-transaction rule rather than as unreadable
		rule bool
	}{
		"create without IF NOT EXISTS": {"CREATE INDEX CONCURRENTLY ix ON t (a);", true},
		"unnamed index":                {"CREATE INDEX CONCURRENTLY ON t (a);", true},
		"drop without IF EXISTS":       {"DROP INDEX CONCURRENTLY ix;", true},
		"transaction control":          {"BEGIN; CREATE INDEX CONCURRENTLY IF NOT EXISTS ix ON t (a); COMMIT;", true},
		"begin atomic body":            {"CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; END;", true},
		"qualified index name":         {"CREATE INDEX CONCURRENTLY IF NOT EXISTS s.ix ON t (a);", false},
		"only comments":                {"-- proudauth:no-transaction\n/* nothing */\n", false},
	} {
		_, err := parseNoTransaction(tc.src)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if errors.Is(err, errNoTxRefused) != tc.rule {
			t.Errorf("%s: %v", name, err)
		}
	}
}
