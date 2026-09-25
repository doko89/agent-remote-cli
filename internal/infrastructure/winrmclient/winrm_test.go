package winrmclient

import (
	"errors"
	"testing"

	"agent-remote/internal/domain"
)

func TestClassification(t *testing.T) {
	if !isAuth(errors.New("401 Unauthorized")) {
		t.Fatal("401 must be auth")
	}
	if !isAuth(errors.New("Logon failure: bad password")) {
		t.Fatal("logon failure must be auth")
	}
	if isAuth(errors.New("connection refused")) {
		t.Fatal("refused must not be auth")
	}
	if !isTimeoutMsg(errTimeout{}) {
		t.Fatal("net timeout must map to timeout")
	}
	if !isTimeoutMsg(errors.New("context deadline exceeded")) {
		t.Fatal("deadline must map to timeout")
	}
	if got := classify(errors.New("401 boom")); string(domain.CodeOf(got)) != "auth_failed" {
		t.Fatalf("got %v", got)
	}
	if got := classify(errTimeout{}); string(domain.CodeOf(got)) != "timeout" {
		t.Fatalf("got %v", got)
	}
	if got := classify(errors.New("refused")); string(domain.CodeOf(got)) != "connection_failed" {
		t.Fatalf("got %v", got)
	}
}

func TestNewClientConstruction(t *testing.T) {
	f := Factory{}
	h := domain.Host{Name: "w", Protocol: domain.ProtocolWinRM, Address: "10.0.0.9",
		User: "admin", Auth: domain.AuthEnv, AuthRef: "V", WinRMTransport: "https", WinRMInsecure: true}
	c, err := f.NewClient(h, "pw")
	if err != nil {
		t.Fatalf("construction must not dial: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := f.NewClient(h, ""); domain.CodeOf(err) != domain.CodeSecretUnavailable {
		t.Fatalf("empty password must fail, got %v", err)
	}
}

type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }
