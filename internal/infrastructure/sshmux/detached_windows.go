//go:build windows

package sshmux

import "syscall"

// detached builds SysProcAttr for a background child that survives its
// parent: no console window, and its own process group so Ctrl-C in the
// terminal that launched the CLI does not reach the lingering master.
func detached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
