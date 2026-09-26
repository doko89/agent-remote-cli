// Package secret resolves passwords from env, stdin, or the OS keyring.
// No password is ever accepted as a CLI flag value: flag values leak into
// shell history and the process list.
package secret

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zalando/go-keyring"

	"agent-remote/internal/domain"
)

// Service names the keyring namespace for stored passwords.
const Service = "agent-remote"

// Resolver implements usecase.SecretResolver.
//
// Stdin is read lazily and cached per process so repeated resolutions in
// one invocation consume the pipe only once.
type Resolver struct {
	// Stdin is the source for AuthStdin; nil means os.Stdin at call time.
	Stdin io.Reader

	cachedStdin string
	stdinRead   bool
}

// Resolve returns the password for h, or "" when the auth method needs none.
func (r *Resolver) Resolve(h domain.Host) (string, error) {
	switch h.Auth {
	case domain.AuthNone:
		return "", nil
	case domain.AuthKeyFile:
		// The "secret" for a key is its passphrase, referenced by env.
		if h.PassphraseEnv == "" {
			return "", nil
		}
		v, ok := os.LookupEnv(h.PassphraseEnv)
		if !ok {
			return "", domain.Fail(domain.CodeSecretUnavailable,
				fmt.Sprintf("environment variable %s is not set", h.PassphraseEnv))
		}
		return v, nil
	case domain.AuthEnv:
		v, ok := os.LookupEnv(h.AuthRef)
		if !ok {
			return "", domain.Fail(domain.CodeSecretUnavailable,
				fmt.Sprintf("environment variable %s is not set", h.AuthRef))
		}
		return v, nil
	case domain.AuthStdin:
		return r.readStdin()
	case domain.AuthKeyring:
		pw, err := keyring.Get(Service, h.Name)
		if err != nil {
			return "", domain.Fail(domain.CodeSecretUnavailable,
				fmt.Sprintf("no keyring secret for host %s: %v", h.Name, err))
		}
		return pw, nil
	default:
		return "", domain.Fail(domain.CodeInvalidInput, "unsupported auth method")
	}
}

// readStdin consumes the whole pipe, trailing newline trimmed. A TTY is
// refused: blocking an agent on an invisible prompt is worse than failing.
func (r *Resolver) readStdin() (string, error) {
	if r.stdinRead {
		return r.cachedStdin, nil
	}
	r.stdinRead = true
	src := r.Stdin
	if src == nil {
		src = os.Stdin
	}
	if f, ok := src.(*os.File); ok && isTTY(f) {
		return "", domain.Fail(domain.CodeSecretUnavailable,
			"password over stdin requires a pipe; refusing to block on a TTY")
	}
	raw, err := io.ReadAll(src)
	if err != nil {
		return "", domain.Fail(domain.CodeSecretUnavailable, "cannot read password from stdin: "+err.Error())
	}
	r.cachedStdin = strings.TrimRight(string(raw), "\r\n")
	return r.cachedStdin, nil
}

// Save stores pw in the OS keyring under the host name.
func Save(hostName, pw string) error {
	if err := keyring.Set(Service, hostName, pw); err != nil {
		return domain.Fail(domain.CodeSecretUnavailable, "cannot store secret in keyring: "+err.Error())
	}
	return nil
}

// Load returns the stored keyring password for a host, or an error when no
// entry exists (renames distinguish "no stored secret" from failures).
func Load(hostName string) (string, error) {
	pw, err := keyring.Get(Service, hostName)
	if err != nil {
		return "", domain.Fail(domain.CodeSecretUnavailable,
			fmt.Sprintf("no keyring secret for host %s: %v", hostName, err))
	}
	return pw, nil
}

// Delete removes a keyring entry. Like Resolver.Delete it treats missing
// entries and unavailable keyrings as best-effort: callers must not fail
// host management over secret cleanup.
func Delete(hostName string) {
	_ = keyring.Delete(Service, hostName)
}

// Delete removes the host's keyring entry, if any. Missing entries and
// unavailable keyrings are not errors: host removal must always succeed.
func (r *Resolver) Delete(hostName string) error {
	_ = keyring.Delete(Service, hostName)
	return nil
}
