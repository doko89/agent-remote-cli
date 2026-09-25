// Package configstore implements usecase.HostStore as a local JSON file.
// The file holds only secret references (never values) and is written
// atomically with owner-only permissions.
package configstore

import (
	"encoding/json"
	"os"
	"path/filepath"

	"agent-remote/internal/domain"
)

// Store is a file-backed host store. The zero value is unusable;
// build it with DefaultPath or an explicit path.
type Store struct {
	Path string
}

// DefaultPath resolves the config location: $AGENT_REMOTE_CONFIG when set,
// otherwise ~/.config/agent-remote/hosts.json.
func DefaultPath() (string, error) {
	if p := os.Getenv("AGENT_REMOTE_CONFIG"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "agent-remote", "hosts.json"), nil
}

// Load reads all hosts. A missing file means "no hosts yet", not an error.
func (s Store) Load() (map[string]domain.Host, error) {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]domain.Host{}, nil
		}
		return nil, err
	}
	if len(raw) == 0 {
		return map[string]domain.Host{}, nil
	}
	var hosts map[string]domain.Host
	if err := json.Unmarshal(raw, &hosts); err != nil {
		return nil, err
	}
	if hosts == nil {
		hosts = map[string]domain.Host{}
	}
	return hosts, nil
}

// Save replaces the whole file atomically (write temp + rename) so a crash
// mid-write never leaves a half-written config behind.
func (s Store) Save(hosts map[string]domain.Host) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".hosts-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup; a successful rename makes this a no-op.
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.Path)
}
