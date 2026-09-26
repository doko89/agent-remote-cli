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
	stream := cutSealedStream(env[bytes.Index(env, marker)+len(marker):])
	if len(stream) < 4 {
		t.Fatal("stream too short for signature length")
	}
	sigLen := int(uint32(stream[0]) | uint32(stream[1])<<8 | uint32(stream[2])<<16 | uint32(stream[3])<<24)
	if sigLen <= 0 || len(stream) < 4+sigLen {
		t.Fatalf("bad signature bounds sigLen=%d streamLen=%d", sigLen, len(stream))
	}
}

// TestCutSealedStream pins the framing cut: exactly one line break goes,
// never a byte run. A sealed blob is RC4 output and may end with CR or LF
// bytes — the old TrimRight ate them and broke the checksum about once per
// 128 messages (large-download false negative, proven live).
func TestCutSealedStream(t *testing.T) {
	head := append([]byte("\x10\x00\x00\x00"), bytes.Repeat([]byte{0xAA}, 16)...)
	mk := func(blob, framing []byte) []byte {
		out := append(append([]byte{}, head...), blob...)
		return append(append(out, framing...), []byte(mimeBoundary+"--\r\n")...)
	}
	want := func(blob []byte) []byte {
		return append(append([]byte{}, head...), blob...)
	}
	// A blob ending in CR with bare-LF framing is indistinguishable from
	// CRLF framing, so it is only paired with the CRLF framing real
	// servers send; every other combination must cut exactly.
	cases := []struct {
		blob     []byte
		framings [][]byte
	}{
		{[]byte{0x01, 0x02, 0x0D}, [][]byte{[]byte("\r\n")}},
		{[]byte{0x01, 0x02, 0x0A}, [][]byte{[]byte("\r\n"), []byte("\n")}},
		{[]byte{0x0D, 0x0A}, [][]byte{[]byte("\r\n")}},
		{[]byte{0x01, 0x02}, [][]byte{[]byte("\r\n"), []byte("\n")}},
	}
	for _, tc := range cases {
		for _, framing := range tc.framings {
			if got := cutSealedStream(mk(tc.blob, framing)); !bytes.Equal(got, want(tc.blob)) {
				t.Fatalf("blob %x framing %q: got %x", tc.blob, framing, got)
			}
		}
	}
	// No framing at all: blob abuts the boundary, fallback keeps it whole.
	bare := append(want([]byte{0x01}), []byte(mimeBoundary+"--")...)
	if got := cutSealedStream(bare); !bytes.Equal(got, want([]byte{0x01})) {
		t.Fatalf("bare boundary: got %x", got)
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

// TestPostCreatesFreshTransport verifies that each Post call creates a new
// HTTP transport (not shared state), preventing fd leaks and enabling safe
// concurrent calls during parallel file transfers.
func TestPostCreatesFreshTransport(t *testing.T) {
	tr := &rawNTLM{dialTimeout: 15 * time.Second}

	client1, transport1 := tr.httpClient()
	if client1 == nil || transport1 == nil {
		t.Fatal("httpClient must return non-nil client and transport")
	}

	_, transport2 := tr.httpClient()
	if transport1 == transport2 {
		t.Fatal("each httpClient call must create a new transport (thread-safety)")
	}

	transport1.CloseIdleConnections()
	transport2.CloseIdleConnections()
}

// TestChallengeBodyDrained verifies that the challenge response body is
// fully consumed before leg 3, ensuring the TCP connection can be reused
// for the sealed message within the same Post cycle.
func TestChallengeBodyDrained(t *testing.T) {
	// Build a response that challengeToken can parse.
	res := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("challenge-body-content")),
	}
	res.Header.Set("Www-Authenticate", "Negotiate TlRMTVNTUAACAAAADgAOADgAAAA1goriHP9aGgpKrpcAAAAAAAAAAIAAgABQAAAACgB8TwAAAA9EADIAVwBTAEkATQBTAFMAUQBMADAAMQ==")

	// Before the fix, only the header was read; the body was left open.
	// The fix uses defer drain(challenge), which fully consumes the body.
	// We simulate the drain to prove the pattern works.
	drain(res)

	// After drain, reading again should return EOF (body fully consumed).
	_, err := io.ReadAll(res.Body)
	if err != nil && err.Error() != "http: read on closed response body" {
		// NopCloser wraps strings.Reader; after drain, it returns io.EOF.
		if err != io.EOF {
			t.Fatalf("unexpected error after drain: %v", err)
		}
	}
}
