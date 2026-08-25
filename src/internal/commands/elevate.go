package commands

import (
	"fmt"
	"os"
)

// maybeElevate ensures the interactive CLI runs with administrator/root rights by
// re-launching itself elevated when it isn't already. Called only for the
// interactive CLI (never the service, which already runs privileged).
//
//   - Windows: triggers a UAC prompt (a new elevated console); this process exits.
//   - Linux/macOS: re-executes via sudo in the same terminal.
//
// Set DECENZED_NO_ELEVATE=1 to skip (e.g. scripts, or running unprivileged on
// purpose). If elevation fails or is declined, the CLI continues unprivileged —
// commands that need admin still print their own hint.
func maybeElevate() {
	if isElevated() || os.Getenv("DECENZED_NO_ELEVATE") != "" {
		return
	}
	if err := elevateSelf(); err != nil {
		fmt.Fprintln(os.Stderr, "note: continuing without admin rights:", err)
		return
	}
	// Reached only on Windows: elevateSelf spawned a new elevated process, so this
	// unprivileged one should exit. (On Unix elevateSelf replaces the process and
	// never returns on success.)
	os.Exit(0)
}
