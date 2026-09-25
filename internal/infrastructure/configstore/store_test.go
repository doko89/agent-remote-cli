package configstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-remote/internal/domain"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := Store{Path: filepath.Join(dir, "sub", "hosts.json")}
	hosts := map[string]domain.Host{
		"web1": {
			Name: "web1", Protocol: domain.ProtocolSSH,
			Address: "10.0.0.1", Port: 22, User: "deploy",
			Auth:    domain.AuthEnv,
			AuthRef: "DEPLOY_PW",
			Filter:  domain.DefaultFilter(),
		},
	}
	if err := s.Save(hosts); err != nil {
		t.Fatal(err)
	}
	// Owner-only permissions on the config file.
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("config perm = %o, want 600", fi.Mode().Perm())
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got["web1"].AuthRef != "DEPLOY_PW" || got["web1"].User != "deploy" {
		t.Fatalf("round trip lost data: %+v", got["web1"])
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "nope.json")}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %v", got)
	}
}

func TestDefaultPathEnvOverride(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", "/tmp/custom.json")
	p, err := DefaultPath()
	if err != nil || p != "/tmp/custom.json" {
		t.Fatalf("got %q, %v", p, err)
	}
}

func TestStoredFileNeverHoldsSecrets(t *testing.T) {
	dir := t.TempDir()
	s := Store{Path: filepath.Join(dir, "hosts.json")}
	h := domain.Host{Name: "w", Protocol: domain.ProtocolWinRM, Address: "h",
		User: "u", Auth: domain.AuthKeyring, Filter: domain.DefaultFilter()}
	if err := s.Save(map[string]domain.Host{"w": h}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(s.Path)
	var decoded map[string]map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for k := range decoded["w"] {
		if k == "password" || k == "secret" || k == "passphrase" {
			t.Fatalf("secret-looking key %q persisted", k)
		}
	}
	if strings.Contains(string(raw), "s3cr3t") {
		t.Fatal("secret value leaked into file")
	}
}

func TestLoadEmptyFileIsEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts.json")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := (Store{Path: p}).Load()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestDefaultPathWithoutEnv(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", "")
	p, err := DefaultPath()
	if err != nil || !strings.HasSuffix(p, filepath.Join(".config", "agent-remote", "hosts.json")) {
		t.Fatalf("got %q, %v", p, err)
	}
}

func TestSaveFailsWhenParentIsFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := Store{Path: filepath.Join(blocker, "hosts.json")}
	if err := s.Save(map[string]domain.Host{}); err == nil {
		t.Fatal("expected MkdirAll failure")
	}
}

func TestLoadDirectoryErrors(t *testing.T) {
	// A directory at the config path fails ReadFile with a non-NotExist
	// error: must surface, not masquerade as "no hosts".
	dir := t.TempDir()
	if _, err := (Store{Path: dir}).Load(); err == nil {
		t.Fatal("expected error when config path is a directory")
	}
}

func TestLoadCorruptFileErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts.json")
	if err := os.WriteFile(p, []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Store{Path: p}).Load(); err == nil {
		t.Fatal("expected error for corrupt config")
	}
}
