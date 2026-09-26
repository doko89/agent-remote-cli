// Package domain holds the core business concepts of agent-remote.
// It has no external dependencies: no SSH, WinRM, CLI, or file I/O imports.
package domain

// Protocol is the transport used to reach a host.
type Protocol string

const (
	ProtocolSSH   Protocol = "ssh"
	ProtocolWinRM Protocol = "winrm"
)

// Valid reports whether p is a supported protocol.
func (p Protocol) Valid() bool {
	return p == ProtocolSSH || p == ProtocolWinRM
}

// AuthMethod names how a secret is resolved at execution time.
// The secret value itself is never stored in the Host record.
type AuthMethod string

const (
	// AuthKeyring reads the password from the OS keyring.
	AuthKeyring AuthMethod = "keyring"
	// AuthEnv reads the password from the named environment variable.
	AuthEnv AuthMethod = "env"
	// AuthStdin reads the password from standard input (pipe only).
	AuthStdin AuthMethod = "stdin"
	// AuthKeyFile uses an SSH private key; no password is stored.
	AuthKeyFile AuthMethod = "keyfile"
	// AuthNone performs no authentication (useful only against test doubles).
	AuthNone AuthMethod = "none"
)

// Valid reports whether m is a supported auth method.
func (m AuthMethod) Valid() bool {
	switch m {
	case AuthKeyring, AuthEnv, AuthStdin, AuthKeyFile, AuthNone:
		return true
	}
	return false
}

// Host is one stored remote configuration entry.
// It carries only references to secrets, never secret values.
type Host struct {
	Name     string   `json:"name"`
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`

	User string `json:"user"`

	// Auth describes where the password/passphrase comes from.
	Auth AuthMethod `json:"auth"`
	// AuthRef is the environment variable name (AuthEnv) or key path
	// (AuthKeyFile). Unused for keyring/stdin/none.
	AuthRef string `json:"auth_ref,omitempty"`
	// Group is an optional label for fan-out targeting (exec --group).
	Group string `json:"group,omitempty"`
	// PassphraseEnv names the env var holding an encrypted key's
	// passphrase (SSH keyfile only). Empty means an unencrypted key, or a
	// passphrase supplied one-shot at exec time.
	PassphraseEnv string `json:"passphrase_env,omitempty"`

	// WinRM-only options.
	WinRMTransport string `json:"winrm_transport,omitempty"` // http | https
	WinRMInsecure  bool   `json:"winrm_insecure,omitempty"`  // skip TLS verify

	// Filter holds per-host banner-filter customization.
	Filter FilterConfig `json:"filter"`
}

// DefaultPort returns the conventional port for h.Protocol when Port is 0.
func (h Host) DefaultPort() int {
	if h.Port != 0 {
		return h.Port
	}
	if h.Protocol == ProtocolWinRM {
		return 5985
	}
	return 22
}

// FilterConfig customizes banner filtering for one host.
type FilterConfig struct {
	// Enabled=false disables Lapis-2 filtering entirely (raw output).
	Enabled bool `json:"enabled"`
	// ExtraPatterns are user-supplied regexes, one per line match.
	ExtraPatterns []string `json:"extra_patterns,omitempty"`
}

// DefaultFilter returns the default filter state: enabled, no extras.
func DefaultFilter() FilterConfig {
	return FilterConfig{Enabled: true}
}
