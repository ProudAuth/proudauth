package storage

import (
	"errors"
	"fmt"
	"strings"
)

// The statement splitter of no-transaction migrations (OPS-008). A file
// marked "-- proudauth:no-transaction" runs one statement at a time, because
// PostgreSQL refuses CREATE INDEX CONCURRENTLY in a transaction block and
// runs a query string of several statements as one. The splitter is
// deliberately conservative: migrations are controlled content, so anything
// it cannot tokenize with certainty is refused rather than guessed. It
// understands single-quoted strings (with '' and, in E'' strings, backslash
// escapes), quoted identifiers, -- and nested /* */ comments, dollar quoting
// and parentheses; it refuses BEGIN ATOMIC function bodies (whose semicolons
// are not quoted), transaction control and psql meta-commands. String
// parsing assumes standard_conforming_strings = on, which the runner sets for
// the session that executes the statements.

type sqlTokenKind int

const (
	tokWord        sqlTokenKind = iota // unquoted identifier or keyword
	tokQuotedIdent                     // "identifier"
	tokString                          // '...', E'...', B'...', X'...', N'...', U&'...', $tag$...$tag$
	tokOther                           // numbers, parameters, operators, punctuation, U&"identifiers"
)

type sqlToken struct {
	kind sqlTokenKind
	text string
}

// sqlStatement is one statement of a no-transaction migration.
type sqlStatement struct {
	// SQL is the statement as sent to the server: its text up to, not
	// including, the terminating semicolon, comments included.
	SQL    string
	tokens []sqlToken
}

// indexDDL is a CREATE INDEX statement of a no-transaction migration: the
// runner rebuilds an invalid index of that name left by an interrupted
// build and checks pg_index.indisvalid before recording the migration.
type indexDDL struct {
	// Name is the index name as PostgreSQL stores it (case-folded unless
	// quoted); Table is the table as written, for to_regclass.
	Name, Table  string
	Concurrently bool
}

// noTxStatement is a validated statement of a no-transaction migration.
type noTxStatement struct {
	SQL   string
	Index *indexDDL // set for CREATE INDEX
	// Concurrently marks CREATE INDEX CONCURRENTLY and DROP INDEX
	// CONCURRENTLY, which run without lock_timeout (applyWithoutTx).
	Concurrently bool
}

func isSQLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= 0x80
}

func isIdentCont(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' || c == '$' }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// scanQuoted returns the index just past the literal or identifier opened by
// the quote character at src[i]; a doubled quote is an escaped quote and,
// when backslash is set (E'...' strings), so is a backslash-escaped character.
func scanQuoted(src string, i int, backslash bool) (int, error) {
	q := src[i]
	for j := i + 1; j < len(src); j++ {
		switch {
		case backslash && src[j] == '\\':
			j++
		case src[j] == q:
			if j+1 < len(src) && src[j+1] == q {
				j++
				continue
			}
			if q == '"' && j == i+1 {
				return 0, fmt.Errorf("zero-length quoted identifier at offset %d", i)
			}
			return j + 1, nil
		}
	}
	if q == '"' {
		return 0, fmt.Errorf("unterminated quoted identifier at offset %d", i)
	}
	return 0, fmt.Errorf("unterminated string literal at offset %d", i)
}

// dollarTag returns the opening delimiter ($$ or $tag$) at src[i], if any.
func dollarTag(src string, i int) (string, bool) {
	j := i + 1
	if j < len(src) && isIdentStart(src[j]) {
		for j++; j < len(src) && isIdentCont(src[j]) && src[j] != '$'; j++ {
		}
	}
	if j < len(src) && src[j] == '$' {
		return src[i : j+1], true
	}
	return "", false
}

// splitSQL splits src into statements at semicolons outside strings,
// identifiers, comments, dollar quotes and parentheses. Statements made only
// of comments are dropped; a missing semicolon after the last statement is
// accepted.
func splitSQL(src string) ([]sqlStatement, error) {
	var out []sqlStatement
	var toks []sqlToken
	start, depth := 0, 0
	end := func(at int) error {
		if depth != 0 {
			return fmt.Errorf("unbalanced parentheses in statement ending at offset %d", at)
		}
		if len(toks) > 0 {
			out = append(out, sqlStatement{SQL: strings.TrimSpace(src[start:at]), tokens: toks})
		}
		toks = nil
		return nil
	}
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case isSQLSpace(c):
			i++
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			if nl := strings.IndexByte(src[i:], '\n'); nl >= 0 {
				i += nl + 1
			} else {
				i = len(src)
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			// PostgreSQL block comments nest.
			nest, j := 1, i+2
			for ; j < len(src) && nest > 0; j++ {
				switch {
				case src[j] == '/' && j+1 < len(src) && src[j+1] == '*':
					nest++
					j++
				case src[j] == '*' && j+1 < len(src) && src[j+1] == '/':
					nest--
					j++
				}
			}
			if nest > 0 {
				return nil, fmt.Errorf("unterminated block comment at offset %d", i)
			}
			i = j
		case c == '\'' || c == '"':
			j, err := scanQuoted(src, i, false)
			if err != nil {
				return nil, err
			}
			kind := tokString
			if c == '"' {
				kind = tokQuotedIdent
			}
			toks = append(toks, sqlToken{kind, src[i:j]})
			i = j
		case c == '$':
			if i+1 < len(src) && isDigit(src[i+1]) {
				j := i + 1
				for j < len(src) && isDigit(src[j]) {
					j++
				}
				toks = append(toks, sqlToken{tokOther, src[i:j]})
				i = j
				continue
			}
			tag, ok := dollarTag(src, i)
			if !ok {
				return nil, fmt.Errorf("unexpected $ at offset %d", i)
			}
			closeAt := strings.Index(src[i+len(tag):], tag)
			if closeAt < 0 {
				return nil, fmt.Errorf("unterminated dollar-quoted string %s at offset %d", tag, i)
			}
			j := i + len(tag) + closeAt + len(tag)
			toks = append(toks, sqlToken{tokString, src[i:j]})
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < len(src) && isIdentCont(src[j]) {
				j++
			}
			word := src[i:j]
			switch {
			case j < len(src) && src[j] == '\'' && (word == "E" || word == "e"):
				k, err := scanQuoted(src, j, true)
				if err != nil {
					return nil, err
				}
				toks = append(toks, sqlToken{tokString, src[i:k]})
				i = k
			case j < len(src) && src[j] == '\'' && len(word) == 1 && strings.ContainsAny(word, "bBxXnN"):
				k, err := scanQuoted(src, j, false)
				if err != nil {
					return nil, err
				}
				toks = append(toks, sqlToken{tokString, src[i:k]})
				i = k
			case (word == "U" || word == "u") && j+1 < len(src) && src[j] == '&' && (src[j+1] == '\'' || src[j+1] == '"'):
				k, err := scanQuoted(src, j+1, false)
				if err != nil {
					return nil, err
				}
				kind := tokString
				if src[j+1] == '"' {
					kind = tokOther // a Unicode-escaped identifier is never case-folded here
				}
				toks = append(toks, sqlToken{kind, src[i:k]})
				i = k
			default:
				toks = append(toks, sqlToken{tokWord, word})
				i = j
			}
		case isDigit(c) || c == '.' && i+1 < len(src) && isDigit(src[i+1]):
			j := i + 1
			for j < len(src) && (isIdentCont(src[j]) || src[j] == '.') && src[j] != '$' {
				// 1.5e-3: the exponent sign belongs to the number.
				if (src[j] == 'e' || src[j] == 'E') && j+1 < len(src) && (src[j+1] == '-' || src[j+1] == '+') {
					j++
				}
				j++
			}
			toks = append(toks, sqlToken{tokOther, src[i:j]})
			i = j
		case c == '\\':
			return nil, fmt.Errorf("backslash outside a string at offset %d (psql meta-commands are not SQL)", i)
		case c == ';' && depth == 0:
			if err := end(i); err != nil {
				return nil, err
			}
			i++
			start = i
		default:
			switch c {
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					return nil, fmt.Errorf("unbalanced parentheses at offset %d", i)
				}
			}
			toks = append(toks, sqlToken{tokOther, string(c)})
			i++
		}
	}
	if err := end(len(src)); err != nil {
		return nil, err
	}
	return out, nil
}

// keyword reports whether the token is the unquoted keyword kw.
func (t sqlToken) keyword(kw string) bool { return t.kind == tokWord && strings.EqualFold(t.text, kw) }

// keywords reports whether toks start with the unquoted keywords kws.
func keywords(toks []sqlToken, kws ...string) bool {
	if len(toks) < len(kws) {
		return false
	}
	for i, kw := range kws {
		if !toks[i].keyword(kw) {
			return false
		}
	}
	return true
}

// identName returns the name PostgreSQL stores for an identifier token:
// unquoted identifiers fold to lower case, quoted ones keep their case.
func identName(t sqlToken) (string, bool) {
	switch t.kind {
	case tokWord:
		return strings.ToLower(t.text), true
	case tokQuotedIdent:
		return strings.ReplaceAll(t.text[1:len(t.text)-1], `""`, `"`), true
	}
	return "", false
}

var errNoTxRefused = errors.New("not allowed in a no-transaction migration")

// parseNoTransaction splits a no-transaction migration and checks each
// statement: a file that runs outside a transaction is not atomic, so it may
// not contain transaction control, and every CREATE INDEX and DROP INDEX in
// it must be repeatable (IF NOT EXISTS / IF EXISTS) so that a run
// interrupted part-way completes when it is repeated.
func parseNoTransaction(body string) ([]noTxStatement, error) {
	stmts, err := splitSQL(body)
	if err != nil {
		return nil, err
	}
	if len(stmts) == 0 {
		return nil, errors.New("no statements")
	}
	var out []noTxStatement
	for n, s := range stmts {
		toks := s.tokens
		for i := 0; i+1 < len(toks); i++ {
			if toks[i].keyword("BEGIN") && toks[i+1].keyword("ATOMIC") {
				return nil, fmt.Errorf("statement %d: BEGIN ATOMIC bodies are %w; use a dollar-quoted body", n+1, errNoTxRefused)
			}
		}
		for _, kw := range []string{"BEGIN", "START", "COMMIT", "END", "ROLLBACK", "ABORT", "SAVEPOINT", "RELEASE"} {
			if toks[0].keyword(kw) {
				return nil, fmt.Errorf("statement %d: transaction control (%s) is %w", n+1, strings.ToUpper(kw), errNoTxRefused)
			}
		}
		st := noTxStatement{SQL: s.SQL}
		switch {
		case keywords(toks, "CREATE", "INDEX") || keywords(toks, "CREATE", "UNIQUE", "INDEX"):
			ix, err := parseCreateIndex(toks)
			if err != nil {
				return nil, fmt.Errorf("statement %d: %w", n+1, err)
			}
			st.Index = ix
			st.Concurrently = ix.Concurrently
		case keywords(toks, "DROP", "INDEX"):
			rest := toks[2:]
			if len(rest) > 0 && rest[0].keyword("CONCURRENTLY") {
				st.Concurrently = true
				rest = rest[1:]
			}
			if !keywords(rest, "IF", "EXISTS") {
				return nil, fmt.Errorf("statement %d: DROP INDEX without IF EXISTS is %w (it must be repeatable)", n+1, errNoTxRefused)
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// parseCreateIndex reads CREATE [UNIQUE] INDEX [CONCURRENTLY] IF NOT EXISTS
// name ON [ONLY] [schema.]table.
func parseCreateIndex(toks []sqlToken) (*indexDDL, error) {
	ix := &indexDDL{}
	i := 2
	if toks[1].keyword("UNIQUE") {
		i = 3
	}
	if i < len(toks) && toks[i].keyword("CONCURRENTLY") {
		ix.Concurrently = true
		i++
	}
	if !keywords(toks[i:], "IF", "NOT", "EXISTS") {
		return nil, fmt.Errorf("CREATE INDEX without IF NOT EXISTS and a name is %w (it must be repeatable)", errNoTxRefused)
	}
	i += 3
	if i >= len(toks) {
		return nil, errors.New("CREATE INDEX without an index name")
	}
	name, ok := identName(toks[i])
	if !ok || toks[i].keyword("ON") {
		return nil, fmt.Errorf("CREATE INDEX: cannot read the index name %q", toks[i].text)
	}
	ix.Name = name
	i++
	if i >= len(toks) || !toks[i].keyword("ON") {
		return nil, fmt.Errorf("CREATE INDEX %s: expected ON after the index name", toks[i-1].text)
	}
	i++
	if i < len(toks) && toks[i].keyword("ONLY") {
		i++
	}
	var table []string
	for {
		if i >= len(toks) {
			return nil, fmt.Errorf("CREATE INDEX %s: missing table name", ix.Name)
		}
		if _, ok := identName(toks[i]); !ok {
			return nil, fmt.Errorf("CREATE INDEX %s: cannot read the table name at %q", ix.Name, toks[i].text)
		}
		table = append(table, toks[i].text)
		i++
		if i < len(toks) && toks[i].kind == tokOther && toks[i].text == "." {
			i++
			continue
		}
		break
	}
	if len(table) > 2 {
		return nil, fmt.Errorf("CREATE INDEX %s: table name %s has too many parts", ix.Name, strings.Join(table, "."))
	}
	ix.Table = strings.Join(table, ".")
	return ix, nil
}
