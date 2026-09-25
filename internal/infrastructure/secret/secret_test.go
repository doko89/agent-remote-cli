package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-remote/internal/domain"
)

func TestResolveEnv(t *testing.T) {
	t.Setenv("AR_TEST_PW", "hunter2")
	r := &Resolver{}
	got, err := r.Resolve(domain.Host{Auth: domain.AuthEnv, AuthRef: "AR_TEST_PW"})
	if err != nil || got != "hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := r.Resolve(domain.Host{Auth: domain.AuthEnv, AuthRef: "AR_TEST_MISSING_XYZ"}); domain.CodeOf(err) != domain.CodeSecretUnavailable {
		t.Fatalf("expected secret_unavailable, got %v", err)
	}
}

func TestResolveStdinCaches(t *testing.T) {
	r := &Resolver{Stdin: strings.NewReader("piped-pw\n")}
	first, err := r.Resolve(domain.Host{Auth: domain.AuthStdin})
	if err != nil || first != "piped-pw" {
		t.Fatalf("got %q, %v", first, err)
	}
	second, err := r.Resolve(domain.Host{Auth: domain.AuthStdin})
	if err != nil || second != "piped-pw" {
		t.Fatalf("second read must hit cache: %q, %v", second, err)
	}
}

func TestResolveStdinRefusesCharacterDevice(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer devnull.Close()
	r := &Resolver{Stdin: devnull}
	if _, err := r.Resolve(domain.Host{Auth: domain.AuthStdin}); domain.CodeOf(err) != domain.CodeSecretUnavailable {
		t.Fatalf("expected refusal on char device, got %v", err)
	}
}

func TestResolveKeyfilePassphrase(t *testing.T) {
	r := &Resolver{}
	got, err := r.Resolve(domain.Host{Auth: domain.AuthKeyFile})
	if err != nil || got != "" {
		t.Fatalf("unencrypted key must resolve empty: %q, %v", got, err)
	}
	t.Setenv("AR_TEST_PHRASE", "phrase")
	got, err = r.Resolve(domain.Host{Auth: domain.AuthKeyFile, PassphraseEnv: "AR_TEST_PHRASE"})
	if err != nil || got != "phrase" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := r.Resolve(domain.Host{Auth: domain.AuthKeyFile, PassphraseEnv: "AR_TEST_MISSING_XYZ"}); domain.CodeOf(err) != domain.CodeSecretUnavailable {
		t.Fatalf("expected secret_unavailable, got %v", err)
	}
}

func TestResolveNoneAndUnknown(t *testing.T) {
	r := &Resolver{}
	if got, err := r.Resolve(domain.Host{Auth: domain.AuthNone}); err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := r.Resolve(domain.Host{Auth: "bogus"}); domain.CodeOf(err) != domain.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %v", err)
	}
}

func TestResolveStdinFromRealFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(p, []byte("file-pw\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := &Resolver{Stdin: f}
	got, err := r.Resolve(domain.Host{Auth: domain.AuthStdin})
	if err != nil || got != "file-pw" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDeleteNeverFails(t *testing.T) {
	if err := (&Resolver{}).Delete("no-such-host"); err != nil {
		t.Fatalf("Delete must be best-effort: %v", err)
	}
}
