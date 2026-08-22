//go:build !windows

package winconsole

// PauseIfDoubleClicked is a no-op on non-Windows platforms (there is no
// double-click-launches-a-console behaviour to work around).
func PauseIfDoubleClicked() {}
