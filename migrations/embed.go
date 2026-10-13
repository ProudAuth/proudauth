// Package migrations embeds the ordered SQL schema migrations.
package migrations

import "embed"

// Files holds every *.sql migration, applied in lexical order.
//
//go:embed *.sql
var Files embed.FS
