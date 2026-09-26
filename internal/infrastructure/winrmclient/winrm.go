// Package winrmclient implements usecase ports over WinRM.
//
// The protocol is request/response by nature, so Lapis 1 needs no work:
// no interactive shell exists to emit MOTD noise. Commands run through
// PowerShell (-NoProfile -NonInteractive is handled by the library's RunPS
// path); the exact interpreter is documented in help output.
package winrmclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/masterzen/winrm"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

// testCommand is a read-only probe: it changes nothing on the target.
const testCommand = `Write-Output "ok"`

// Factory builds connected WinRM clients.
type Factory struct {
	// DialTimeout bounds the underlying TCP connection.
	DialTimeout time.Duration
}

// NewClient builds the endpoint and verifies credentials lazily: the winrm
// library authenticates on first request, so NewClient only validates input
// and defers network errors to Test/Exec where they are classified.
func (f Factory) NewClient(h domain.Host, password string) (usecase.RemoteClient, error) {
	if password == "" {
		return nil, domain.Fail(domain.CodeSecretUnavailable, "empty password for winrm auth")
	}
	https := strings.EqualFold(h.WinRMTransport, "https")
	port := h.DefaultPort()
	ep := winrm.NewEndpoint(h.Address, port, https, h.WinRMInsecure, nil, nil, nil, 0)
	if f.DialTimeout > 0 {
		ep.Timeout = f.DialTimeout
	} else {
		ep.Timeout = 15 * time.Second
	}
	// Raw NTLM is the default: some Windows hosts advertise only Negotiate
	// yet reject SPNEGO-wrapped NTLM while accepting raw NTLM (verified
	// live; matches pywinrm/requests-ntlm behavior). Basic auth stays
	// unavailable unless the server enables it.
	transport := &rawNTLM{user: h.User, password: password}
	params := winrm.NewParameters("PT60S", "en-US", 153600)
	params.TransportDecorator = func() winrm.Transporter {
		return transport
	}
	c, err := winrm.NewClientWithParameters(ep, h.User, password, params)
	if err != nil {
		return nil, classify(err)
	}
	return &client{inner: c, transport: transport}, nil
}

type client struct {
	inner     *winrm.Client
	transport *rawNTLM
}

func (c *client) Close() error { return nil }

// Test runs a read-only probe with exponential-backoff retries. Retrying is
// safe here because the probe has no side effects; Exec must never retry.
func (c *client) Test(ctx context.Context) (domain.TestResult, error) {
	start := time.Now()
	var last error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		c.transport.setContext(ctx)
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return domain.TestResult{}, domain.Fail(domain.CodeTimeout, "winrm test timed out")
			case <-time.After(backoff):
				backoff *= 2
			}
		}
		_, _, _, err := c.inner.RunPSWithContext(ctx, testCommand)
		if err == nil {
			return domain.TestResult{Reachable: true, LatencyMs: time.Since(start).Milliseconds()}, nil
		}
		if isAuth(err) || ctx.Err() != nil {
			return domain.TestResult{}, classify(err)
		}
		last = err
	}
	return domain.TestResult{}, classify(last)
}

// Exec runs cmd exactly once via PowerShell. No retry: re-running could
// repeat side effects on the target.
func (c *client) Exec(ctx context.Context, cmd string) (domain.ExecResult, error) {
	start := time.Now()
	c.transport.setContext(ctx)
	stdout, stderr, code, err := c.inner.RunPSWithContext(ctx, cmd)
	res := domain.ExecResult{
		Stdout:     stdout,
		Stderr:     stderr,
		ExitCode:   code,
		DurationMs: time.Since(start).Milliseconds(),
	}
	if err != nil {
		if ctx.Err() != nil {
			return res, domain.Fail(domain.CodeTimeout, "winrm command timed out: "+err.Error())
		}
		return res, classify(err)
	}
	return res, nil
}

func classify(err error) error {
	switch {
	case isAuth(err):
		return domain.Fail(domain.CodeAuthFailed, "winrm authentication failed: "+err.Error())
	case isTimeoutMsg(err):
		return domain.Fail(domain.CodeTimeout, "winrm operation timed out: "+err.Error())
	default:
		return domain.Fail(domain.CodeConnectionFailed, "winrm operation failed: "+err.Error())
	}
}

func isAuth(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "401") || strings.Contains(m, "unauthorized") ||
		strings.Contains(m, "access is denied") || strings.Contains(m, "logon failure")
}

func isTimeoutMsg(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "timed out") || strings.Contains(m, "timeout") ||
		strings.Contains(m, "deadline exceeded")
}
