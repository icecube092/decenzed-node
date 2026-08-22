//go:build windows

package winconsole

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// PauseIfDoubleClicked keeps the console window open when the program was
// launched by a double-click from Explorer. In that case the freshly-created
// console has only this ONE process attached and it would vanish the instant we
// exit. When started from an existing terminal (cmd/PowerShell/Git Bash) the
// console has more than one process, so we don't pause.
func PauseIfDoubleClicked() {
	var pids [4]uint32
	r, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if int(r) <= 1 {
		fmt.Print("\nPress Enter to exit...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
