package storage

import "io/fs"

// SetMigrationFS substitutes the migration source for a test.
func SetMigrationFS(f fs.FS) (restore func()) {
	old := migrationFS
	migrationFS = f
	return func() { migrationFS = old }
}
