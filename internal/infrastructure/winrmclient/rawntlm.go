package winrmclient

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	bodgitntlm "github.com/bodgit/ntlmssp"
	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

// rawNTLM is a winrm.Transporter that speaks raw NTLM tokens under the
// Negotiate scheme (Authorization: Negotiate <raw NTLMSSP blob>) instead of
// SPNEGO-wrapped tokens.
//
// Some Windows hosts advertise only `WWW-Authenticate: Negotiate` yet reject
// SPNEGO-wrapped NTLM while accepting raw NTLM under the Negotiate scheme
// (the behavior of pywinrm/requests-ntlm, verified live against such a
// host). The library's stock ClientNTLM always SPNEGO-wraps, so this
// transport performs the three-leg handshake manually with raw tokens.
type rawNTLM struct {
	user     string
	password string

	url         string
	dialTimeout time.Duration
	insecure    bool
	http        *http.Client // fresh per Post, see httpClient
}

func (t *rawNTLM) Transport(ep *winrm.Endpoint) error {
	scheme := "http"
	if ep.HTTPS {
		scheme = "https"
	}
	t.url = fmt.Sprintf("%s://%s:%d/wsman", scheme, ep.Host, ep.Port)
	t.dialTimeout = ep.Timeout
	if t.dialTimeout <= 0 {
		t.dialTimeout = 15 * time.Second
	}
	t.insecure = ep.Insecure
	return nil
}

// httpClient builds a FRESH client per SOAP message. NTLM state lives on the
// TCP connection: reusing an already-authenticated connection for a new
// handshake confuses picky servers (empty 500s), while legs within one Post
// still share their connection via keep-alive. Cost is a few extra TCP
// handshakes per command on a LAN — negligible for a management tool.
func (t *rawNTLM) httpClient() *http.Client {
	dialer := &net.Dialer{Timeout: t.dialTimeout, KeepAlive: 30 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: t.insecure}, //nolint:gosec // opt-in via --insecure
			ResponseHeaderTimeout: t.dialTimeout,
		},
		// Safety cap only; per-command bounds come from the use-case
		// context enforced by the caller around RunPSWithContext.
		Timeout: 10 * time.Minute,
	}
}

// Post runs the payload through a fresh NTLM handshake per SOAP message,
// mirroring the library's error shape (status code in the message) so error
// classification keeps working.
func (t *rawNTLM) Post(_ *winrm.Client, msg *soap.SoapMessage) (string, error) {
	t.http = t.httpClient()
	payload := msg.String()

	user, domain := splitUser(t.user)
	workstation, _ := os.Hostname()
	// Mirrors pywinrm/requests-ntlm semantics: empty domain unless the user
	// gave one explicitly, real workstation, full LMv2/session-key responses.
	nc, err := bodgitntlm.NewClient(
		bodgitntlm.SetUserInfo(user, t.password),
		bodgitntlm.SetDomain(domain),
		bodgitntlm.SetWorkstation(workstation),
	)
	if err != nil {
		return "", fmt.Errorf("ntlm negotiate: %w", err)
	}
	type1, err := nc.Authenticate(nil, nil)
	if err != nil {
		return "", fmt.Errorf("ntlm negotiate: %w", err)
	}

	// Leg 1+2: anonymous probe, then the Type1 message; the second
	// response carries the Type2 challenge. Bodies are drained before
	// close: NTLM is connection-bound, so every leg must reuse the same
	// TCP connection and Go only reuses fully-consumed ones.
	anon, err := t.round(payload, "")
	if err != nil {
		return "", err
	}
	drain(anon)
	challenge, err := t.round(payload, authScheme+base64.StdEncoding.EncodeToString(type1))
	if err != nil {
		return "", err
	}
	token, err := challengeToken(challenge)
	if err != nil {
		return "", fmt.Errorf("ntlm challenge: %w", err)
	}
	rawChallenge, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("ntlm challenge: %w", err)
	}
	type3, err := nc.Authenticate(rawChallenge, nil)
	if err != nil {
		return "", fmt.Errorf("ntlm authenticate: %w", err)
	}
	// Servers with AllowUnencrypted=false require the SOAP message sealed
	// with the NTLM session keys (same wire format as pywinrm). The sealed
	// payload rides on the Type3 leg.
	sealed, err := sealMessage(nc, payload)
	if err != nil {
		return "", fmt.Errorf("ntlm seal: %w", err)
	}
	final, err := t.roundSealed(sealed, authScheme+base64.StdEncoding.EncodeToString(type3))
	if err != nil {
		return "", err
	}
	defer final.Body.Close()
	if ct := final.Header.Get(headerContentType); strings.Contains(ct, `protocol="application/HTTP-SPNEGO-session-encrypted"`) {
		soapText, err := unsealResponse(nc, final)
		if err != nil {
			return "", err
		}
		return soapText, nil
	}
	raw, err := io.ReadAll(final.Body)
	if err != nil {
		return "", fmt.Errorf("http response error: %d - %w", final.StatusCode, err)
	}
	if final.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http error %d: %s", final.StatusCode, strings.TrimSpace(string(raw)))
	}
	return string(raw), nil
}

// protocolString mirrors the NTLM encrypted-session MIME protocol.
const protocolString = "application/HTTP-SPNEGO-session-encrypted"

// authScheme carries raw NTLMSSP tokens (not SPNEGO-wrapped).
const authScheme = "Negotiate "

// headerContentType is the HTTP header set on every WinRM request.
const headerContentType = "Content-Type"

const mimeBoundary = "--Encrypted Boundary"

// sealMessage wraps the SOAP payload in the encrypted multipart envelope.
func sealMessage(nc *bodgitntlm.Client, payload string) ([]byte, error) {
	sess := nc.SecuritySession()
	if sess == nil {
		return nil, fmt.Errorf("no NTLM security session")
	}
	sealed, signature, err := sess.Wrap([]byte(payload))
	if err != nil {
		return nil, err
	}
	stream := append(u32le(len(signature)), signature...)
	stream = append(stream, sealed...)
	return []byte(fmt.Sprintf(
		"%s\r\n\tContent-Type: %s\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n%s\r\n\tContent-Type: application/octet-stream\r\n%s%s--\r\n",
		mimeBoundary, protocolString, len(payload), mimeBoundary, stream, mimeBoundary)), nil
}

// roundSealed POSTs a sealed envelope with the encrypted content type.
func (t *rawNTLM) roundSealed(sealed []byte, auth string) (*http.Response, error) {
	req, err := http.NewRequest("POST", t.url, bytes.NewReader(sealed)) //nolint:noctx // bounded by http.Client.Timeout
	if err != nil {
		return nil, fmt.Errorf("impossible to create http request %w", err)
	}
	req.Header.Set(headerContentType, fmt.Sprintf(`multipart/encrypted;protocol="%s";boundary="Encrypted Boundary"`, protocolString))
	req.Header.Set("Authorization", auth)
	res, err := t.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unknown error %w", err)
	}
	return res, nil
}

// unsealResponse decrypts a multipart/encrypted SOAP response. Layout mirrors
// sealMessage: the sealed octet-stream sits between the octet-stream MIME
// header and the closing boundary.
func unsealResponse(nc *bodgitntlm.Client, res *http.Response) (string, error) {
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("http response error: %d - %w", res.StatusCode, err)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http error %d: encrypted response failed", res.StatusCode)
	}
	marker := []byte("\tContent-Type: application/octet-stream\r\n")
	start := bytes.Index(raw, marker)
	if start < 0 {
		return "", fmt.Errorf("no sealed stream in response")
	}
	stream := raw[start+len(marker):]
	if end := bytes.LastIndex(stream, []byte(mimeBoundary)); end >= 0 {
		stream = stream[:end]
	}
	stream = bytes.TrimRight(stream, "\r\n")
	if len(stream) < 4 {
		return "", fmt.Errorf("truncated sealed stream")
	}
	sigLen := int(binary.LittleEndian.Uint32(stream[:4]))
	if len(stream) < 4+sigLen {
		return "", fmt.Errorf("truncated sealed stream")
	}
	decrypted, err := nc.SecuritySession().Unwrap(stream[4+sigLen:], stream[4:4+sigLen])
	if err != nil {
		return "", fmt.Errorf("ntlm unseal: %w", err)
	}
	if want := originalLength(raw); want >= 0 && len(decrypted) != want {
		return "", fmt.Errorf("decrypted length %d != advertised %d", len(decrypted), want)
	}
	return string(decrypted), nil
}

// originalLength reads the Length= advertisement from the MIME headers.
func originalLength(raw []byte) int {
	idx := bytes.Index(raw, []byte("Length="))
	if idx < 0 {
		return -1
	}
	rest := raw[idx+len("Length="):]
	end := bytes.IndexAny(rest, "\r\n;")
	if end < 0 {
		return -1
	}
	n, err := strconv.Atoi(string(bytes.TrimSpace(rest[:end])))
	if err != nil {
		return -1
	}
	return n
}

func u32le(n int) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(n))
	return b[:]
}

// round POSTs payload with an optional Authorization header, returning the
// response for the caller to consume. A 401 without credentials is the
// expected handshake step, not an error.
func (t *rawNTLM) round(payload, auth string) (*http.Response, error) {
	req, err := http.NewRequest("POST", t.url, strings.NewReader(payload)) //nolint:noctx // bounded by http.Client.Timeout
	if err != nil {
		return nil, fmt.Errorf("impossible to create http request %w", err)
	}
	req.Header.Set(headerContentType, "application/soap+xml;charset=UTF-8")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := t.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unknown error %w", err)
	}
	return res, nil
}

func drain(res *http.Response) {
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

// challengeToken extracts the challenge token from a WWW-Authenticate
// header. Servers answering a raw NTLM Type1 may echo either scheme.
func challengeToken(res *http.Response) (string, error) {
	defer drain(res)
	if res.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("http error %d: expected 401 challenge", res.StatusCode)
	}
	for _, h := range res.Header.Values("Www-Authenticate") {
		if rest, ok := strings.CutPrefix(h, "NTLM "); ok && rest != "" {
			return rest, nil
		}
		if rest, ok := strings.CutPrefix(h, authScheme); ok && rest != "" {
			return rest, nil
		}
	}
	return "", fmt.Errorf("http error %d: server did not issue an NTLM challenge", res.StatusCode)
}

func splitUser(u string) (user, domain string) {
	if parts := strings.SplitN(u, "\\", 2); len(parts) == 2 {
		return parts[1], parts[0]
	}
	return u, ""
}
