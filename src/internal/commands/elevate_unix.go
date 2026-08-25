//go:build !windows

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// isElevated reports whether the process runs as root.
func isElevated() bool { return os.Geteuid() == 0 }

// elevateSelf re-executes this binary through sudo in the same terminal (sudo
// prompts for the password inline). On success it replaces the process image and
// never returns.
func elevateSelf() error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("sudo not found; run as root")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	argv := append([]string{"sudo", exe}, os.Args[1:]...)
	return syscall.Exec(sudo, argv, os.Environ())
}
