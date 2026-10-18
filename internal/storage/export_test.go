package storage

import (
	"io/fs"
	"time"
)

// SetMigrationFS substitutes the migration source for a test.
func SetMigrationFS(f fs.FS) (restore func()) {
	old := migrationFS
	migrationFS = f
	return func() { migrationFS = old }
}

// WithLockRetryBackoff shortens the first pause between attempts of a
// migration that gave up waiting for a lock.
func WithLockRetryBackoff(opt MigrateOptions, d time.Duration) MigrateOptions {
	opt.lockRetryBackoff = d
	return opt
}
