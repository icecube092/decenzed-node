package commands

// Constrained to Windows by the _windows.go filename suffix (no build tag or
// -tags needed).

import (
	"os"
	"os/exec"
)

// execSelf re-launches this binary and exits the current process. Windows has no
// exec() that replaces the process image, so we start a child that inherits the
// same console (stdin/stdout/stderr) and then exit — the child takes over the
// terminal on the new version. Returns only if the child failed to start.
func execSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
