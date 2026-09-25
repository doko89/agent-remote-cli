package winrmclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	bodgitntlm "github.com/bodgit/ntlmssp"

	"agent-remote/internal/domain"
)

// recordedChallenge is a real Type2 challenge captured from a Windows host
// that enforces NTLM + message encryption. It holds only public nonce data
// (no secret) and lets the seal path be exercised without a live server:
// all NTLM crypto after the challenge is local computation.
const recordedChallenge = "TlRMTVNTUAACAAAAGAAYADgAAAA1goriHP9aGgpKrpcAAAAAAAAAAIAAgABQAAAACgB8TwAAAA9EADIAVwBTAEkATQBTAFMAUQBMADAAMQACABgARAAyAFcAUwBJAE0AUwBTAFEATAAwADEAAQAYAEQAMgBXAFMASQBNAFMAUwBRAEwAMAAxAAQAGABkADIAdwBzAGkAbQBzAHMAcQBsADAAMQADABgAZAAyAHcAcwBpAG0AcwBzAHEAbAAwADEABwAIAKNqx3mkTN0BAAAAAA=="

func TestSplitUser(t *testing.T) {
	u, d := splitUser("administrator")
	if u != "administrator" || d != "" {
		t.Fatalf("got %q %q", u, d)
	}
	u, d = splitUser(`HOST\administrator`)
	if u != "administrator" || d != "HOST" {
		t.Fatalf("got %q %q", u, d)
	}
}

func TestChallengeToken(t *testing.T) {
	mk := func(status int, headers ...string) *http.Response {
		r := &http.Response{StatusCode: status, Header: http.Header{}}
		for _, h := range headers {
			k, v, _ := strings.Cut(h, ": ")
			r.Header.Add(k, v)
		}
		r.Body = io.NopCloser(strings.NewReader(""))
		return r
	}
	if tok, err := challengeToken(mk(401, "Www-Authenticate: NTLM abc123")); err != nil || tok != "abc123" {
		t.Fatalf("raw NTLM: %q %v", tok, err)
	}
	if tok, err := challengeToken(mk(401, "Www-Authenticate: Negotiate xyz")); err != nil || tok != "xyz" {
		t.Fatalf("negotiate: %q %v", tok, err)
	}
	if _, err := challengeToken(mk(401, "Www-Authenticate: Negotiate")); err == nil {
		t.Fatal("bare scheme must fail")
	}
	if _, err := challengeToken(mk(200)); err == nil {
		t.Fatal("non-401 must fail")
	}
}

func TestOriginalLength(t *testing.T) {
	if n := originalLength([]byte("Length=42\r\n")); n != 42 {
		t.Fatalf("got %d", n)
	}
	if n := originalLength([]byte("nothing")); n != -1 {
		t.Fatalf("got %d", n)
	}
}

// TestSealEnvelopeShape drives the bodgit NTLM client through a recorded
// server challenge, then checks the sealed envelope carries a verifiable
// Length advertisement and a well-formed sealed stream. Proven live: the
// same envelope shape authenticates and executes against a real host with
// AllowUnencrypted=false.
func TestSealEnvelopeShape(t *testing.T) {
	nc, err := bodgitntlm.NewClient(
		bodgitntlm.SetUserInfo("administrator", "dummy"),
		bodgitntlm.SetDomain(""),
		bodgitntlm.SetWorkstation("testbox"),
	)
	if err != nil {
		t.Fatal(err)
	}
	rawChallenge, err := base64.StdEncoding.DecodeString(recordedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nc.Authenticate(rawChallenge, nil); err != nil {
		t.Fatalf("recorded challenge must drive a session: %v", err)
	}
	if nc.SecuritySession() == nil {
		t.Fatal("no security session after challenge")
	}
	env, err := sealMessage(nc, "<s:Envelope/>")
	if err != nil {
		t.Fatal(err)
	}
	text := string(env)
	for _, want := range []string{
		mimeBoundary,
		"Content-Type: application/HTTP-SPNEGO-session-encrypted",
		"OriginalContent: type=application/soap+xml;charset=UTF-8;Length=13",
		"Content-Type: application/octet-stream",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("envelope missing %q:\n%s", want, text)
		}
	}
	// The sealed stream must self-describe: Length= matches the payload, and
	// the length-prefixed signature bounds hold (the exact fields
	// unsealResponse relies on). Crypto round-trip itself is proven live by
	// TestLiveWinRM: NTLM sealing is directional, so a client session cannot
	// unseal its own output — only the server side can.
	if n := originalLength(env); n != 13 {
		t.Fatalf("advertised length = %d", n)
	}
	marker := []byte("\tContent-Type: application/octet-stream\r\n")
	stream := env[bytes.Index(env, marker)+len(marker):]
	if end := bytes.LastIndex(stream, []byte(mimeBoundary)); end >= 0 {
		stream = stream[:end]
	}
	stream = bytes.TrimRight(stream, "\r\n")
	if len(stream) < 4 {
		t.Fatal("stream too short for signature length")
	}
	sigLen := int(uint32(stream[0]) | uint32(stream[1])<<8 | uint32(stream[2])<<16 | uint32(stream[3])<<24)
	if sigLen <= 0 || len(stream) < 4+sigLen {
		t.Fatalf("bad signature bounds sigLen=%d streamLen=%d", sigLen, len(stream))
	}
}

// TestLiveWinRM runs the full stack against a real Windows host. It is
// skipped unless AGENT_REMOTE_WINRM_LIVE=host,user,pass is set, so normal
// `go test ./...` never dials out. Run it explicitly to re-prove NTLM +
// message sealing after touching this package.
func TestLiveWinRM(t *testing.T) {
	spec := strings.SplitN(os.Getenv("AGENT_REMOTE_WINRM_LIVE"), ",", 3)
	if len(spec) != 3 || spec[0] == "" {
		t.Skip("set AGENT_REMOTE_WINRM_LIVE=host,user,pass for live WinRM proof")
	}
	h := domain.Host{Name: "live", Protocol: domain.ProtocolWinRM, Address: spec[0],
		User: spec[1], Auth: domain.AuthNone, Filter: domain.DefaultFilter()}
	c, err := Factory{}.NewClient(h, spec[2])
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := c.Test(ctx); err != nil {
		t.Fatalf("test: %v", err)
	}
	res, err := c.Exec(ctx, "hostname")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.ExitCode != 0 || strings.TrimSpace(res.Stdout) == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
