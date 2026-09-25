package usecase

import (
	"sort"
	"strings"

	"agent-remote/internal/domain"
)

// AddHostInput gathers the fields of `add ssh|winrm`. Secret values never
// appear here: only how the secret is resolved later.
type AddHostInput struct {
	Name     string
	Protocol domain.Protocol

	Address string
	Port    int
	User    string

	Auth    domain.AuthMethod
	AuthRef string // env var name (env) or key path (keyfile)
	// PassphraseEnv names the env var with an encrypted key's passphrase
	// (SSH keyfile only).
	PassphraseEnv string

	WinRMTransport string // http | https, winrm only
	WinRMInsecure  bool   // winrm only

	ExtraFilterPatterns []string
	FilterDisabled      bool
}

// ValidateAdd checks the input against the domain contract. Protocol-specific
// rules live here so `add ssh --help` and `add winrm --help` each only
// expose flags that can pass for their protocol.
func ValidateAdd(in AddHostInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return domain.Fail(domain.CodeInvalidInput, "host name must not be empty")
	}
	if !in.Protocol.Valid() {
		return domain.Fail(domain.CodeInvalidInput, "unsupported protocol")
	}
	if strings.TrimSpace(in.Address) == "" {
		return domain.Fail(domain.CodeInvalidInput, "address must not be empty")
	}
	if in.Port < 0 || in.Port > 65535 {
		return domain.Fail(domain.CodeInvalidInput, "port must be between 0 and 65535")
	}
	if strings.TrimSpace(in.User) == "" {
		return domain.Fail(domain.CodeInvalidInput, "user must not be empty")
	}
	if !in.Auth.Valid() {
		return domain.Fail(domain.CodeInvalidInput, "unsupported auth method")
	}
	switch in.Protocol {
	case domain.ProtocolSSH:
		if in.WinRMTransport != "" {
			return domain.Fail(domain.CodeInvalidInput, "winrm transport is not valid for ssh hosts")
		}
		if in.Auth == domain.AuthEnv && strings.TrimSpace(in.AuthRef) == "" {
			return domain.Fail(domain.CodeInvalidInput, "env auth requires an environment variable name")
		}
		if in.Auth == domain.AuthKeyFile && strings.TrimSpace(in.AuthRef) == "" {
			return domain.Fail(domain.CodeInvalidInput, "keyfile auth requires a private key path")
		}
		if in.PassphraseEnv != "" && in.Auth != domain.AuthKeyFile {
			return domain.Fail(domain.CodeInvalidInput, "passphrase env is only valid with keyfile auth")
		}
	case domain.ProtocolWinRM:
		if in.Auth == domain.AuthKeyFile {
			return domain.Fail(domain.CodeInvalidInput, "keyfile auth is not valid for winrm hosts")
		}
		if in.Auth == domain.AuthEnv && strings.TrimSpace(in.AuthRef) == "" {
			return domain.Fail(domain.CodeInvalidInput, "env auth requires an environment variable name")
		}
		if t := strings.ToLower(in.WinRMTransport); t != "" && t != "http" && t != "https" {
			return domain.Fail(domain.CodeInvalidInput, "winrm transport must be http or https")
		}
	}
	if _, err := domain.CompilePatterns(in.ExtraFilterPatterns); err != nil {
		return err
	}
	return nil
}

// AddHost registers a new host. An existing name is rejected, never silently
// overwritten, so an agent cannot accidentally clobber a working config.
func AddHost(store HostStore, in AddHostInput) (domain.Host, error) {
	if err := ValidateAdd(in); err != nil {
		return domain.Host{}, err
	}
	hosts, err := store.Load()
	if err != nil {
		return domain.Host{}, domain.Fail(domain.CodeStoreError, "cannot load host store: "+err.Error())
	}
	if _, exists := hosts[in.Name]; exists {
		return domain.Host{}, domain.Fail(domain.CodeHostExists, "host "+in.Name+" already exists; remove it first or pick another name")
	}
	h := domain.Host{
		Name:          in.Name,
		Protocol:      in.Protocol,
		Address:       in.Address,
		Port:          in.Port,
		User:          in.User,
		Auth:          in.Auth,
		AuthRef:       in.AuthRef,
		PassphraseEnv: in.PassphraseEnv,
		Filter:        domain.FilterConfig{Enabled: !in.FilterDisabled, ExtraPatterns: in.ExtraFilterPatterns},
	}
	if in.Protocol == domain.ProtocolWinRM {
		h.WinRMTransport = strings.ToLower(in.WinRMTransport)
		if h.WinRMTransport == "" {
			h.WinRMTransport = "http"
		}
		h.WinRMInsecure = in.WinRMInsecure
	}
	hosts[in.Name] = h
	if err := store.Save(hosts); err != nil {
		return domain.Host{}, domain.Fail(domain.CodeStoreError, "cannot save host store: "+err.Error())
	}
	return h, nil
}

// RemoveHost deletes a host and its stored secret (if any). The secret
// cleanup is best-effort: a keyring failure must not leave the host behind.
func RemoveHost(store HostStore, secrets SecretResolver, name string) error {
	hosts, err := store.Load()
	if err != nil {
		return domain.Fail(domain.CodeStoreError, "cannot load host store: "+err.Error())
	}
	if _, exists := hosts[name]; !exists {
		return domain.Fail(domain.CodeHostNotFound, "host "+name+" not found")
	}
	delete(hosts, name)
	if err := store.Save(hosts); err != nil {
		return domain.Fail(domain.CodeStoreError, "cannot save host store: "+err.Error())
	}
	_ = secrets.Delete(name)
	return nil
}

// ListHosts returns all hosts ordered by name. Store and presenter layers
// must never attach secret values; the Host type cannot carry them.
func ListHosts(store HostStore) ([]domain.Host, error) {
	hosts, err := store.Load()
	if err != nil {
		return nil, domain.Fail(domain.CodeStoreError, "cannot load host store: "+err.Error())
	}
	out := make([]domain.Host, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ShowHost returns one host by name.
func ShowHost(store HostStore, name string) (domain.Host, error) {
	hosts, err := store.Load()
	if err != nil {
		return domain.Host{}, domain.Fail(domain.CodeStoreError, "cannot load host store: "+err.Error())
	}
	h, exists := hosts[name]
	if !exists {
		return domain.Host{}, domain.Fail(domain.CodeHostNotFound, "host "+name+" not found")
	}
	return h, nil
}
