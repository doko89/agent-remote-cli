// Package usecase holds application business rules. It defines ports
// (interfaces) that infrastructure must satisfy; it never imports
// infrastructure packages.
package usecase

import (
	"context"
	"time"

	"agent-remote/internal/domain"
)

// HostStore persists host configurations.
type HostStore interface {
	Load() (map[string]domain.Host, error)
	Save(hosts map[string]domain.Host) error
}

// SecretResolver resolves the password/passphrase for a host at exec time.
type SecretResolver interface {
	Resolve(h domain.Host) (secret string, err error)
	// Delete removes a stored secret (keyring) for the host; a no-op when
	// the host keeps no stored secret. It must never fail the removal of
	// the host itself.
	Delete(hostName string) error
}

// RemoteClient runs commands against one host. Implementations must use
// non-interactive execution (no PTY for SSH) and surface pre-auth banners
// outside the command streams.
type RemoteClient interface {
	// Test performs a side-effect-free handshake. It may retry internally.
	Test(ctx context.Context) (domain.TestResult, error)
	// Exec runs cmd non-interactively exactly once. It must NOT retry:
	// re-running a command could repeat side effects.
	Exec(ctx context.Context, cmd string) (domain.ExecResult, error)
	Close() error
}

// ClientFactory builds a connected client for a host.
type ClientFactory interface {
	NewClient(h domain.Host, password string) (RemoteClient, error)
}

// DefaultTimeout bounds every remote operation when the caller passes none.
const DefaultTimeout = 30 * time.Second

func timeoutOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTimeout
	}
	return d
}
