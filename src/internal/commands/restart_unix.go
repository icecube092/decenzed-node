//go:build !windows

package commands

import (
	"os"
	"syscall"
)

// execSelf replaces the current process image with a fresh run of this binary
// (same args/env), so an updated binary takes effect in-place. On Unix this is a
// clean exec: the PID is kept and control never returns on success.
func execSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
