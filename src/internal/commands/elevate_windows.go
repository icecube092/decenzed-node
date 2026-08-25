package commands

// Constrained to Windows by the _windows.go filename suffix (no build tag or
// -tags needed).

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// isElevated reports whether the current process has an elevated (admin) token.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// elevateSelf re-launches this binary with the "runas" verb, which asks Windows
// for elevation (UAC). It returns after starting the elevated process (which
// runs in its own console); the caller then exits the unprivileged one.
func elevateSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var argPtr *uint16
	if args := strings.Join(os.Args[1:], " "); args != "" {
		argPtr = windows.StringToUTF16Ptr(args)
	}
	return windows.ShellExecute(0,
		windows.StringToUTF16Ptr("runas"),
		windows.StringToUTF16Ptr(exe),
		argPtr, nil, windows.SW_SHOWNORMAL)
}
