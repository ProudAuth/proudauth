package main

import (
	"os"
	"path/filepath"
)

// writePrivateFile writes data to path with mode 0600. os.WriteFile applies
// its mode only when it creates the file, so an existing file would keep
// looser permissions; instead the data goes to a new 0600 file in the same
// directory that is then renamed over path. A symbolic link at path is
// replaced, not followed.
func writePrivateFile(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
