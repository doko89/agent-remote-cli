//go:build unix

package sshmux

import "syscall"

// detached builds SysProcAttr for a background child that survives its
// parent (own session; Setsid alone — combining it with Setpgid makes
// setsid fail with EPERM because setpgid already made the child a group
// leader).
func detached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
