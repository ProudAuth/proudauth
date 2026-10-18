package storage

import (
	"fmt"
	"io/fs"
	"strings"
)

// The migration lint (OPS-008, DEP-012, TEST-061). Every release must keep
// the previous release's binaries working against its schema (expand →
// migrate → contract), and a migration must not hold a lock that stops the
// service's queries for longer than a moment. Both used to rest on review
// alone. LintMigrations reads every migration with the runner's statement
// splitter and reports:
//
//   - lock rules, for DDL that blocks reads or writes of a table that
//     already exists: a plain CREATE INDEX (or ADD UNIQUE / PRIMARY KEY /
//     EXCLUDE, which build an index) instead of CREATE INDEX CONCURRENTLY
//     (blocking-index), ALTER COLUMN ... TYPE and stored generated columns
//     (table-rewrite), ADD COLUMN with a non-constant default, a serial type
//     or an identity (volatile-default). A file allows one with a
//     "-- proudauth:allow-<rule>: <reason>" line;
//   - CONCURRENTLY in a file without "-- proudauth:no-transaction"
//     (concurrently-in-transaction), which the runner refuses at run time;
//   - compatibility rules, for DDL that removes or changes what older
//     binaries use in the mixed-version window: DROP TABLE / COLUMN / INDEX /
//     CONSTRAINT and other DROPs, DROP NOT NULL, SET NOT NULL, DROP DEFAULT,
//     a column type change, RENAME (and SET SCHEMA), ALTER TYPE / DOMAIN and
//     TRUNCATE. A file allows them with "-- proudauth:compat=contract" (read
//     by the runner, which then requires a backup reference) or with
//     "-- proudauth:reviewed-expand: <why older binaries keep working>".
//
// DDL on a table the same file creates is never reported (beyond
// CONCURRENTLY): nothing reads it yet. The lint understands schema-qualified
// and quoted names, IF [NOT] EXISTS, ONLY, several actions in one ALTER
// TABLE, comments and the statements of DO blocks (function bodies run
// only when called and are not read). A statement it cannot classify is not
// reported; a file the splitter cannot read is (unreadable).
// Findings of migrations that were applied before the lint existed cannot be
// fixed, since the runner verifies every applied file's checksum: the
// contract test explains them with a baseline (migrations/lint-baseline.txt),
// and fails on a finding the baseline does not name and on a baseline entry
// that names no finding.

// Lint rules.
const (
	lintBlockingIndex   = "blocking-index"
	lintConcurrentlyTx  = "concurrently-in-transaction"
	lintTableRewrite    = "table-rewrite"
	lintVolatileDefault = "volatile-default"

	lintDropTable      = "drop-table"
	lintDropColumn     = "drop-column"
	lintDropIndex      = "drop-index"
	lintDropConstraint = "drop-constraint"
	lintDropObject     = "drop-object"
	lintDropNotNull    = "drop-not-null"
	lintSetNotNull     = "set-not-null"
	lintDropDefault    = "drop-default"
	lintColumnType     = "column-type"
	lintAlterType      = "alter-type"
	lintRename         = "rename"
	lintTruncate       = "truncate"

	lintUnreadable = "unreadable"
)

// lintLockRules are allowed by "-- proudauth:allow-<rule>: <reason>".
var lintLockRules = map[string]bool{lintBlockingIndex: true, lintTableRewrite: true, lintVolatileDefault: true}

// lintCompatRules are allowed by compat=contract or reviewed-expand.
var lintCompatRules = map[string]bool{
	lintDropTable: true, lintDropColumn: true, lintDropIndex: true, lintDropConstraint: true, lintDropObject: true,
	lintDropNotNull: true, lintSetNotNull: true, lintDropDefault: true, lintColumnType: true, lintAlterType: true,
	lintRename: true, lintTruncate: true,
}

// Migration markers read by the lint and the runner.
const (
	contractMarker        = "-- proudauth:compat=contract"
	reviewedExpandMarker  = "-- proudauth:reviewed-expand:"
	allowOutOfOrderMarker = "-- proudauth:allow-out-of-order:"
	allowRuleMarker       = "-- proudauth:allow-" // + rule + ":"
)

// migrationCompat is a migration's compatibility class: "contract" when the
// file contains the contract marker, otherwise "expand".
func migrationCompat(body string) string {
	if strings.Contains(body, contractMarker) {
		return "contract"
	}
	return "expand"
}

// markerReason returns the reason of a "<prefix> <reason>" line of body
// (prefix ends with the colon): the first such line with a non-blank reason,
// trimmed; "" when there is none.
func markerReason(body, prefix string) string {
	for _, l := range strings.Split(body, "\n") {
		if r, ok := strings.CutPrefix(strings.TrimSpace(l), prefix); ok && strings.TrimSpace(r) != "" {
			return strings.TrimSpace(r)
		}
	}
	return ""
}

// LintFinding is one statement of a migration file the lint reports.
type LintFinding struct {
	File string
	// Line is the line of the statement's first token.
	Line int
	Rule string
	// Subject is what the statement acts on, as PostgreSQL names it: an
	// index, a table, table.column or table.constraint ("-" when it has no
	// name). File, Rule and Subject identify the finding in the baseline.
	Subject string
	Message string
}

func (f LintFinding) String() string {
	return fmt.Sprintf("%s:%d: %s %s: %s", f.File, f.Line, f.Rule, f.Subject, f.Message)
}

// LintBaselineEntry is one line of a lint baseline: a finding of a migration
// that was applied before the lint existed and so cannot change, with the
// reason it was acceptable.
type LintBaselineEntry struct {
	File, Rule, Subject, Reason string
	// Line is the entry's line in the baseline file.
	Line int
}

func (e LintBaselineEntry) String() string {
	return fmt.Sprintf("baseline line %d: %s %s %s", e.Line, e.File, e.Rule, e.Subject)
}

// ParseLintBaseline reads a lint baseline: one "<file> <rule> <subject>
// <reason>" entry per line; blank lines and lines starting with # are
// ignored. Every entry needs a reason.
func ParseLintBaseline(text string) ([]LintBaselineEntry, error) {
	var out []LintBaselineEntry
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			return nil, fmt.Errorf("lint baseline line %d: want \"<file> <rule> <subject> <reason>\", got %q", n+1, line)
		}
		out = append(out, LintBaselineEntry{File: f[0], Rule: f[1], Subject: f[2], Reason: strings.Join(f[3:], " "), Line: n + 1})
	}
	return out, nil
}

// LintMigrations lints every .sql file of fsys in lexical order and returns
// the findings the baseline does not explain and the baseline entries that
// explain no finding. Each entry explains one finding with its file, rule
// and subject, so a file with two such findings needs two entries.
func LintMigrations(fsys fs.FS, baseline []LintBaselineEntry) (unexplained []LintFinding, stale []LintBaselineEntry, err error) {
	findings, err := lintMigrationFiles(fsys)
	if err != nil {
		return nil, nil, err
	}
	unexplained, stale = applyLintBaseline(findings, baseline)
	return unexplained, stale, nil
}

func applyLintBaseline(findings []LintFinding, baseline []LintBaselineEntry) (unexplained []LintFinding, stale []LintBaselineEntry) {
	type key struct{ file, rule, subject string }
	open := map[key][]int{}
	for i, b := range baseline {
		k := key{b.File, b.Rule, b.Subject}
		open[k] = append(open[k], i)
	}
	used := make([]bool, len(baseline))
	for _, f := range findings {
		k := key{f.File, f.Rule, f.Subject}
		if idx := open[k]; len(idx) > 0 {
			used[idx[0]] = true
			open[k] = idx[1:]
			continue
		}
		unexplained = append(unexplained, f)
	}
	for i, b := range baseline {
		if !used[i] {
			stale = append(stale, b)
		}
	}
	return unexplained, stale
}

// lintMigrationFiles returns every finding of the .sql files of fsys, in
// lexical order of the files.
func lintMigrationFiles(fsys fs.FS) ([]LintFinding, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	// Tables created by earlier files: "CREATE TABLE IF NOT EXISTS" of one of
	// them creates nothing, so the file's later DDL on it is DDL on an
	// existing table.
	existing := map[string]bool{}
	var out []LintFinding
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, lintMigration(e.Name(), string(b), existing)...)
	}
	return out, nil
}

// migrationLinter lints one file.
type migrationLinter struct {
	file string
	noTx bool
	// compatAllowed: the file is a contract migration or carries a
	// reviewed-expand reason.
	compatAllowed bool
	// badReview: a reviewed-expand line without a reason after the colon.
	badReview bool
	allowed   map[string]bool // lock rules allowed by allow-<rule> lines
	existing  map[string]bool // tables earlier files created
	created   map[string]bool // tables this file created
	findings  []LintFinding
}

func lintMigration(name, body string, existing map[string]bool) []LintFinding {
	l := &migrationLinter{
		file:          name,
		noTx:          hasLine(body, noTransactionDirective),
		compatAllowed: migrationCompat(body) == "contract" || markerReason(body, reviewedExpandMarker) != "",
		allowed:       map[string]bool{},
		existing:      existing,
		created:       map[string]bool{},
	}
	if !l.compatAllowed {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), strings.TrimSuffix(reviewedExpandMarker, ":")) {
				l.badReview = true
			}
		}
	}
	for rule := range lintLockRules {
		if markerReason(body, allowRuleMarker+rule+":") != "" {
			l.allowed[rule] = true
		}
	}
	stmts, err := splitSQL(body)
	if err != nil {
		l.findings = append(l.findings, LintFinding{File: name, Line: 1, Rule: lintUnreadable, Subject: "-",
			Message: fmt.Sprintf("the statement splitter cannot read this file (%v), so it cannot be checked; write it as plain SQL statements", err)})
		return l.findings
	}
	for _, s := range stmts {
		l.statement(s.tokens, s.line, 0)
	}
	for t := range l.created {
		existing[t] = true
	}
	return l.findings
}

func (l *migrationLinter) report(line int, rule, subject, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	switch {
	case lintLockRules[rule]:
		if l.allowed[rule] {
			return
		}
		msg += fmt.Sprintf("; if it is safe here, say why with a %q line", allowRuleMarker+rule+": <reason>")
	case lintCompatRules[rule]:
		if l.compatAllowed {
			return
		}
		msg += fmt.Sprintf("; mark the file %q (applied only with a backup reference) or explain with %q", contractMarker, reviewedExpandMarker+" <why older binaries keep working>")
		if l.badReview {
			msg += " (its reviewed-expand line needs a reason after the colon)"
		}
	}
	if subject == "" {
		subject = "-"
	}
	l.findings = append(l.findings, LintFinding{File: l.file, Line: line, Rule: rule, Subject: subject, Message: msg})
}

// skipKeywords returns i advanced past the keywords kws when toks[i:] starts
// with them.
func skipKeywords(toks []sqlToken, i int, kws ...string) int {
	if i <= len(toks) && keywords(toks[i:], kws...) {
		return i + len(kws)
	}
	return i
}

func isPunct(toks []sqlToken, i int, p string) bool {
	return i < len(toks) && toks[i].kind == tokOther && toks[i].text == p
}

// lintName reads a possibly schema-qualified name at toks[i] and returns it
// as PostgreSQL stores it (parts joined by ".", unquoted parts folded to
// lower case, the schema public dropped) and the index after it.
func lintName(toks []sqlToken, i int) (string, int, bool) {
	var parts []string
	for {
		if i >= len(toks) {
			return "", i, false
		}
		p, ok := identName(toks[i])
		if !ok {
			return "", i, false
		}
		parts = append(parts, p)
		i++
		if !isPunct(toks, i, ".") {
			break
		}
		i++
	}
	if len(parts) == 2 && parts[0] == "public" {
		parts = parts[1:]
	}
	return strings.Join(parts, "."), i, true
}

// lintNames reads a comma-separated list of names, as DROP TABLE and
// TRUNCATE take, skipping ONLY and a trailing *.
func lintNames(toks []sqlToken, i int) []string {
	var out []string
	for {
		i = skipKeywords(toks, i, "ONLY")
		name, j, ok := lintName(toks, i)
		if !ok {
			return out
		}
		out = append(out, name)
		i = j
		if isPunct(toks, i, "*") {
			i++
		}
		if !isPunct(toks, i, ",") {
			return out
		}
		i++
	}
}

// orUnread returns names, or "-" when the statement's names could not be
// read: the statement is still reported.
func orUnread(names []string) []string {
	if len(names) == 0 {
		return []string{"-"}
	}
	return names
}

// depthZero calls fn with every token of toks outside parentheses and
// brackets, with its index; fn returns false to stop.
func depthZero(toks []sqlToken, fn func(i int) bool) {
	depth := 0
	for i, t := range toks {
		if t.kind == tokOther {
			switch t.text {
			case "(", "[":
				depth++
				continue
			case ")", "]":
				depth--
				continue
			}
		}
		if depth == 0 && !fn(i) {
			return
		}
	}
}

func hasKeyword(toks []sqlToken, kw string) bool {
	found := false
	depthZero(toks, func(i int) bool {
		found = toks[i].keyword(kw)
		return !found
	})
	return found
}

// tokensText renders tokens for a message.
func tokensText(toks []sqlToken) string {
	var b strings.Builder
	for i, t := range toks {
		if i > 0 && t.kind != tokOther && toks[i-1].kind != tokOther {
			b.WriteByte(' ')
		}
		b.WriteString(t.text)
	}
	return b.String()
}

// statement lints one statement; depth counts the DO blocks around it.
func (l *migrationLinter) statement(toks []sqlToken, line, depth int) {
	if len(toks) == 0 {
		return
	}
	switch {
	case toks[0].keyword("CREATE"):
		l.create(toks, line)
	case keywords(toks, "ALTER", "TABLE"):
		l.alterTable(toks, line)
	case toks[0].keyword("ALTER"):
		l.alterOther(toks, line)
	case toks[0].keyword("DROP"):
		l.drop(toks, line)
	case toks[0].keyword("TRUNCATE"):
		i := skipKeywords(toks, 1, "TABLE")
		for _, t := range orUnread(lintNames(toks, i)) {
			if !l.created[t] {
				l.report(line, lintTruncate, t, "TRUNCATE %s deletes every row older binaries may still read", t)
			}
		}
	case toks[0].keyword("REINDEX"):
		if hasKeyword(toks, "CONCURRENTLY") {
			l.concurrently(line, "REINDEX", "-")
		}
	case toks[0].keyword("DO"):
		l.doBlock(toks, line, depth)
	}
}

func (l *migrationLinter) concurrently(line int, what, subject string) {
	if !l.noTx {
		l.report(line, lintConcurrentlyTx, subject, "%s CONCURRENTLY cannot run in a transaction block, and the runner refuses it there: put it in a file with a %q line", what, noTransactionDirective)
	}
}

func (l *migrationLinter) create(toks []sqlToken, line int) {
	i := skipKeywords(toks, 1, "OR", "REPLACE")
	if i < len(toks) && toks[i].keyword("UNIQUE") {
		i++
	}
	if i < len(toks) && toks[i].keyword("INDEX") {
		l.createIndex(toks, i+1, line)
		return
	}
	for i < len(toks) && (toks[i].keyword("GLOBAL") || toks[i].keyword("LOCAL") || toks[i].keyword("TEMP") ||
		toks[i].keyword("TEMPORARY") || toks[i].keyword("UNLOGGED")) {
		i++
	}
	if i >= len(toks) || !toks[i].keyword("TABLE") {
		return
	}
	i = skipKeywords(toks, i+1, "IF", "NOT", "EXISTS")
	if name, _, ok := lintName(toks, i); ok && !l.existing[name] {
		l.created[name] = true
	}
}

// createIndex reads CREATE [UNIQUE] INDEX [CONCURRENTLY] [[IF NOT EXISTS]
// name] ON [ONLY] table from toks[i] on, after INDEX.
func (l *migrationLinter) createIndex(toks []sqlToken, i, line int) {
	conc := false
	if i < len(toks) && toks[i].keyword("CONCURRENTLY") {
		conc = true
		i++
	}
	i = skipKeywords(toks, i, "IF", "NOT", "EXISTS")
	index, table := "", ""
	if i < len(toks) && !toks[i].keyword("ON") {
		if n, j, ok := lintName(toks, i); ok {
			index, i = n, j
		}
	}
	if i < len(toks) && toks[i].keyword("ON") {
		if n, _, ok := lintName(toks, skipKeywords(toks, i+1, "ONLY")); ok {
			table = n
		}
	}
	subject := index
	if subject == "" {
		subject = table
	}
	if conc {
		l.concurrently(line, "CREATE INDEX", subject)
		return
	}
	if table != "" && l.created[table] {
		return
	}
	if table == "" {
		table = "(unread)"
	}
	l.report(line, lintBlockingIndex, subject, "CREATE INDEX on existing table %s blocks its writes for the whole build: use CREATE INDEX CONCURRENTLY IF NOT EXISTS in a file with a %q line", table, noTransactionDirective)
}

// alterTable reads ALTER TABLE [IF EXISTS] [ONLY] name [*] followed by
// RENAME ..., SET SCHEMA or a comma-separated list of actions.
func (l *migrationLinter) alterTable(toks []sqlToken, line int) {
	if keywords(toks[2:], "ALL", "IN") {
		return // ALTER TABLE ALL IN TABLESPACE
	}
	i := skipKeywords(toks, 2, "IF", "EXISTS")
	i = skipKeywords(toks, i, "ONLY")
	table, i, ok := lintName(toks, i)
	if !ok {
		return
	}
	if isPunct(toks, i, "*") {
		i++
	}
	rest := toks[i:]
	isNew := l.created[table]
	switch {
	case len(rest) > 0 && rest[0].keyword("RENAME"):
		if isNew {
			return
		}
		subject := table
		switch {
		case keywords(rest, "RENAME", "TO"):
		case keywords(rest, "RENAME", "CONSTRAINT"), keywords(rest, "RENAME", "COLUMN"):
			if len(rest) > 2 {
				if n, ok := identName(rest[2]); ok {
					subject = table + "." + n
				}
			}
		case len(rest) > 1:
			if n, ok := identName(rest[1]); ok {
				subject = table + "." + n
			}
		}
		l.report(line, lintRename, subject, "ALTER TABLE %s RENAME renames what older binaries still use by its old name", table)
		return
	case keywords(rest, "SET", "SCHEMA"):
		if !isNew {
			l.report(line, lintRename, table, "ALTER TABLE %s SET SCHEMA moves the table away from the name older binaries use", table)
		}
		return
	}
	// Actions are separated by commas outside parentheses and brackets.
	start := 0
	var actions [][]sqlToken
	depthZero(rest, func(j int) bool {
		if isPunct(rest, j, ",") {
			actions = append(actions, rest[start:j])
			start = j + 1
		}
		return true
	})
	actions = append(actions, rest[start:])
	for _, a := range actions {
		l.alterAction(table, isNew, a, line)
	}
}

func (l *migrationLinter) alterAction(table string, isNew bool, a []sqlToken, line int) {
	if len(a) == 0 {
		return
	}
	if a[0].keyword("DETACH") {
		if hasKeyword(a, "CONCURRENTLY") {
			l.concurrently(line, "DETACH PARTITION", table)
		}
		return
	}
	if isNew {
		return
	}
	switch {
	case a[0].keyword("ADD"):
		l.addAction(table, a[1:], line)
	case keywords(a, "DROP", "CONSTRAINT"):
		subject := table
		if n, _, ok := lintName(a, skipKeywords(a, 2, "IF", "EXISTS")); ok {
			subject = table + "." + n
		}
		l.report(line, lintDropConstraint, subject, "ALTER TABLE %s DROP CONSTRAINT removes a rule older binaries may rely on", table)
	case a[0].keyword("DROP"):
		i := skipKeywords(a, 1, "COLUMN")
		i = skipKeywords(a, i, "IF", "EXISTS")
		subject := table
		if i < len(a) {
			if n, ok := identName(a[i]); ok {
				subject = table + "." + n
			}
		}
		l.report(line, lintDropColumn, subject, "ALTER TABLE %s DROP COLUMN removes a column older binaries may still read or write", table)
	case a[0].keyword("ALTER"):
		if len(a) > 1 && a[1].keyword("CONSTRAINT") {
			return
		}
		i := skipKeywords(a, 1, "COLUMN")
		if i >= len(a) {
			return
		}
		col, ok := identName(a[i])
		if !ok {
			return
		}
		subject, c := table+"."+col, a[i+1:]
		switch {
		case keywords(c, "TYPE"), keywords(c, "SET", "DATA", "TYPE"):
			l.report(line, lintTableRewrite, subject, "ALTER COLUMN %s TYPE rewrites table %s and its indexes under ACCESS EXCLUSIVE, which blocks every read and write", col, table)
			l.report(line, lintColumnType, subject, "changing the type of %s can break older binaries that read or write it", subject)
		case keywords(c, "SET", "NOT", "NULL"):
			l.report(line, lintSetNotNull, subject, "SET NOT NULL on %s refuses the NULLs older binaries may write (and scans the table under ACCESS EXCLUSIVE)", subject)
		case keywords(c, "DROP", "NOT", "NULL"):
			l.report(line, lintDropNotNull, subject, "DROP NOT NULL on %s lets NULLs reach older binaries that assume none", subject)
		case keywords(c, "DROP", "DEFAULT"), keywords(c, "DROP", "IDENTITY"):
			l.report(line, lintDropDefault, subject, "dropping the default of %s breaks inserts of older binaries that leave the column out", subject)
		}
	}
}

// addAction reads ADD [CONSTRAINT name] table_constraint or ADD [COLUMN]
// [IF NOT EXISTS] column definition, from the token after ADD.
func (l *migrationLinter) addAction(table string, a []sqlToken, line int) {
	c, cname := a, ""
	if len(c) > 1 && c[0].keyword("CONSTRAINT") {
		cname, _ = identName(c[1])
		c = c[2:]
	}
	if len(c) > 0 && (c[0].keyword("UNIQUE") || c[0].keyword("PRIMARY") || c[0].keyword("EXCLUDE")) {
		// UNIQUE USING INDEX and PRIMARY KEY USING INDEX adopt an index
		// built beforehand; everything else builds one.
		after := 1
		if c[0].keyword("PRIMARY") {
			after = 2
		}
		if !c[0].keyword("EXCLUDE") && keywords(c[min(after, len(c)):], "USING", "INDEX") && !keywords(c[min(after, len(c)):], "USING", "INDEX", "TABLESPACE") {
			return
		}
		subject := table
		if cname != "" {
			subject = table + "." + cname
		}
		l.report(line, lintBlockingIndex, subject, "ADD %s on existing table %s builds an index under ACCESS EXCLUSIVE, which blocks every read and write: build a unique index with CREATE UNIQUE INDEX CONCURRENTLY in a file with a %q line, then ADD CONSTRAINT ... USING INDEX",
			strings.ToUpper(c[0].text), table, noTransactionDirective)
		return
	}
	if cname != "" || len(c) > 0 && (c[0].keyword("CHECK") || c[0].keyword("FOREIGN")) {
		return
	}
	i := skipKeywords(c, 0, "COLUMN")
	i = skipKeywords(c, i, "IF", "NOT", "EXISTS")
	if i >= len(c) {
		return
	}
	col, ok := identName(c[i])
	if !ok {
		return
	}
	l.columnDefinition(table, table+"."+col, c[i+1:], line)
}

// serialTypes are the column types that imply DEFAULT nextval(...).
var serialTypes = map[string]bool{"serial": true, "serial2": true, "serial4": true, "serial8": true, "smallserial": true, "bigserial": true}

// columnDefinition checks the type and constraints of a column ADD COLUMN
// adds to an existing table.
func (l *migrationLinter) columnDefinition(table, subject string, def []sqlToken, line int) {
	if len(def) > 0 && def[0].kind == tokWord && serialTypes[strings.ToLower(def[0].text)] {
		l.report(line, lintVolatileDefault, subject, "ADD COLUMN %s %s fills every existing row of %s from a sequence, rewriting the table under ACCESS EXCLUSIVE", subject, def[0].text, table)
	}
	depthZero(def, func(i int) bool {
		t := def[i]
		switch {
		case t.keyword("DEFAULT"):
			expr := defaultExpression(def[i+1:])
			if !constantExpression(expr) {
				l.report(line, lintVolatileDefault, subject, "ADD COLUMN %s DEFAULT %s: a volatile default rewrites %s under ACCESS EXCLUSIVE, and a stable one such as now() gives every existing row the migration's value; add the column with a constant default or none, then SET DEFAULT and backfill in batches",
					subject, tokensText(expr), table)
			}
		case t.keyword("GENERATED"):
			if hasKeyword(def[i:], "IDENTITY") {
				l.report(line, lintVolatileDefault, subject, "ADD COLUMN %s GENERATED ... AS IDENTITY fills every existing row of %s from a sequence, rewriting the table under ACCESS EXCLUSIVE", subject, table)
			} else if hasKeyword(def[i:], "STORED") {
				l.report(line, lintTableRewrite, subject, "ADD COLUMN %s GENERATED ... STORED rewrites %s under ACCESS EXCLUSIVE, which blocks every read and write", subject, table)
			}
		case t.keyword("UNIQUE"), t.keyword("PRIMARY"):
			l.report(line, lintBlockingIndex, subject, "ADD COLUMN %s %s builds an index on existing table %s under ACCESS EXCLUSIVE: add the column, then build the index with CREATE UNIQUE INDEX CONCURRENTLY in a file with a %q line",
				subject, strings.ToUpper(t.text), table, noTransactionDirective)
		}
		return true
	})
}

// defaultExpression returns the tokens of a DEFAULT expression: up to the
// next column constraint outside parentheses.
func defaultExpression(toks []sqlToken) []sqlToken {
	end := len(toks)
	depthZero(toks, func(i int) bool {
		for _, kw := range []string{"CONSTRAINT", "CHECK", "DEFAULT", "GENERATED", "UNIQUE", "PRIMARY", "REFERENCES", "DEFERRABLE", "INITIALLY"} {
			if toks[i].keyword(kw) {
				end = i
				return false
			}
		}
		return true
	})
	return toks[:end]
}

// constantFunctions build a constant from constant arguments; any other
// function call in a default is treated as volatile.
var constantFunctions = map[string]bool{
	"json_build_object": true, "jsonb_build_object": true, "json_build_array": true, "jsonb_build_array": true,
	"row": true, "coalesce": true, "nullif": true, "greatest": true, "least": true, "cast": true,
}

// sqlValueFunctions are function calls written without parentheses.
var sqlValueFunctions = map[string]bool{
	"current_date": true, "current_time": true, "current_timestamp": true, "localtime": true, "localtimestamp": true,
	"current_user": true, "current_role": true, "session_user": true, "user": true, "system_user": true,
	"current_catalog": true, "current_schema": true,
}

// constantExpression reports whether a default expression is a constant: no
// function call other than constantFunctions and no SQL value function.
// Type names after :: and AS are not calls, even with modifiers.
func constantExpression(toks []sqlToken) bool {
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case isPunct(toks, i, ":") && isPunct(toks, i+1, ":"):
			i = skipTypeName(toks, i+2) - 1
		case t.keyword("AS"):
			i = skipTypeName(toks, i+1) - 1
		case t.kind == tokWord && sqlValueFunctions[strings.ToLower(t.text)]:
			return false
		case isPunct(toks, i+1, "("):
			if name, ok := identName(t); ok && !constantFunctions[name] {
				return false
			}
		}
	}
	return true
}

// skipTypeName returns the index after a type name at toks[i]: its words
// (double precision, character varying, schema.type), modifiers in
// parentheses and array brackets.
func skipTypeName(toks []sqlToken, i int) int {
	for i < len(toks) && (toks[i].kind == tokWord || toks[i].kind == tokQuotedIdent || isPunct(toks, i, ".")) {
		i++
	}
	if isPunct(toks, i, "(") {
		for depth := 0; i < len(toks); i++ {
			if isPunct(toks, i, "(") {
				depth++
			} else if isPunct(toks, i, ")") {
				if depth--; depth == 0 {
					i++
					break
				}
			}
		}
	}
	for isPunct(toks, i, "[") {
		for i < len(toks) && !isPunct(toks, i, "]") {
			i++
		}
		if i < len(toks) {
			i++
		}
	}
	return i
}

// objectKinds are the object kinds of DROP and ALTER statements that span
// several words.
var objectKinds = [][]string{
	{"MATERIALIZED", "VIEW"}, {"FOREIGN", "DATA", "WRAPPER"}, {"FOREIGN", "TABLE"}, {"EVENT", "TRIGGER"},
	{"TEXT", "SEARCH", "CONFIGURATION"}, {"TEXT", "SEARCH", "DICTIONARY"}, {"TEXT", "SEARCH", "PARSER"},
	{"TEXT", "SEARCH", "TEMPLATE"}, {"ACCESS", "METHOD"}, {"OPERATOR", "CLASS"}, {"OPERATOR", "FAMILY"},
	{"USER", "MAPPING"}, {"OWNED", "BY"},
}

// objectKind returns the object kind of a DROP or ALTER statement, starting
// at toks[i], and the index after it.
func objectKind(toks []sqlToken, i int) (string, int) {
	for _, k := range objectKinds {
		if keywords(toks[min(i, len(toks)):], k...) {
			return strings.Join(k, " "), i + len(k)
		}
	}
	if i < len(toks) && toks[i].kind == tokWord {
		return strings.ToUpper(toks[i].text), i + 1
	}
	return "", i
}

// alterOther handles ALTER statements other than ALTER TABLE: ALTER TYPE and
// ALTER DOMAIN always, other kinds when they RENAME.
func (l *migrationLinter) alterOther(toks []sqlToken, line int) {
	kind, i := objectKind(toks, 1)
	name, _, _ := lintName(toks, skipKeywords(toks, i, "IF", "EXISTS"))
	switch {
	case kind == "TYPE", kind == "DOMAIN":
		l.report(line, lintAlterType, name, "ALTER %s %s changes a type older binaries read and write values of", kind, name)
	case hasKeyword(toks, "RENAME"):
		l.report(line, lintRename, name, "ALTER %s ... RENAME renames what older binaries still use by its old name", kind)
	}
}

func (l *migrationLinter) drop(toks []sqlToken, line int) {
	kind, i := objectKind(toks, 1)
	switch kind {
	case "TABLE":
		for _, t := range orUnread(lintNames(toks, skipKeywords(toks, i, "IF", "EXISTS"))) {
			if l.created[t] {
				delete(l.created, t)
				continue
			}
			delete(l.existing, t)
			l.report(line, lintDropTable, t, "DROP TABLE %s removes a table older binaries may still use", t)
		}
	case "INDEX":
		conc := i < len(toks) && toks[i].keyword("CONCURRENTLY")
		if conc {
			i++
		}
		for _, ix := range orUnread(lintNames(toks, skipKeywords(toks, i, "IF", "EXISTS"))) {
			if conc {
				l.concurrently(line, "DROP INDEX", ix)
			}
			l.report(line, lintDropIndex, ix, "DROP INDEX %s removes an index older binaries' queries or uniqueness may rely on", ix)
		}
	default:
		name, _, _ := lintName(toks, skipKeywords(toks, i, "IF", "EXISTS"))
		l.report(line, lintDropObject, name, "DROP %s %s removes an object older binaries may still use", kind, name)
	}
}

// doBlock lints the statements of a DO block's body, which run when the
// migration runs: a PL/pgSQL statement is checked from its first DDL
// keyword (after BEGIN, IF ... THEN and the like), and EXECUTE of a string
// literal as a statement of its own. Dynamic SQL built at run time cannot be
// checked.
func (l *migrationLinter) doBlock(toks []sqlToken, line, depth int) {
	for _, t := range toks[1:] {
		if t.kind == tokString {
			l.procedural(t.text, line, depth+1)
			return
		}
	}
}

func (l *migrationLinter) procedural(literal string, line, depth int) {
	if depth > 4 {
		return
	}
	var body string
	switch {
	case strings.HasPrefix(literal, "$"):
		tag := literal[:strings.Index(literal[1:], "$")+2]
		body = literal[len(tag) : len(literal)-len(tag)]
	case strings.HasPrefix(literal, "'"):
		body = strings.ReplaceAll(literal[1:len(literal)-1], "''", "'")
	default:
		l.findings = append(l.findings, LintFinding{File: l.file, Line: line, Rule: lintUnreadable, Subject: "-",
			Message: fmt.Sprintf("a DO block or EXECUTE with the literal %.20s... cannot be checked: use a dollar-quoted or plain string", literal)})
		return
	}
	stmts, err := splitSQL(body)
	if err != nil {
		l.findings = append(l.findings, LintFinding{File: l.file, Line: line, Rule: lintUnreadable, Subject: "-",
			Message: fmt.Sprintf("the statement splitter cannot read a DO block or EXECUTE string here (%v), so it cannot be checked", err)})
		return
	}
	for _, s := range stmts {
		t := s.tokens
		depthZero(t, func(i int) bool {
			if t[i].keyword("EXECUTE") && i+1 < len(t) && t[i+1].kind == tokString {
				l.procedural(t[i+1].text, line, depth+1)
			}
			return true
		})
		depthZero(t, func(i int) bool {
			for _, kw := range []string{"CREATE", "ALTER", "DROP", "TRUNCATE", "REINDEX", "DO"} {
				if t[i].keyword(kw) {
					l.statement(t[i:], line, depth)
					return false
				}
			}
			return true
		})
	}
}
