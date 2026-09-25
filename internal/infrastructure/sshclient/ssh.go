// Package sshclient implements usecase ports over SSH.
//
// Lapis 1 (PRD 5.4): commands run through Session.Run with no PTY request,
// so login banners/MOTD tied to interactive shells never enter the streams.
// Pre-auth banners arrive via BannerCallback and are kept in
// ExecResult.PreAuthBanner, never merged into stdout.
package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

// Factory builds connected SSH clients.
type Factory struct {
	// DialTimeout bounds TCP connect + handshake per attempt.
	DialTimeout time.Duration
}

// NewClient connects and authenticates. password is the key passphrase when
// AuthRef points at a key file, otherwise the password credential.
func (f Factory) NewClient(h domain.Host, password string) (usecase.RemoteClient, error) {
	conn, banner, err := dial(h, password, f.DialTimeout)
	if err != nil {
		return nil, err
	}
	return &client{conn: conn, banner: banner}, nil
}

// dial opens one authenticated SSH connection, shared by the exec client
// and the SFTP transfer client. The banner is captured outside the command
// streams (PRD 5.4: pre-auth banners never mix into command output).
func dial(h domain.Host, password string, dialTimeout time.Duration) (*ssh.Client, string, error) {
	if dialTimeout <= 0 {
		dialTimeout = 15 * time.Second
	}
	auths, err := authMethods(h, password)
	if err != nil {
		return nil, "", err
	}
	var banner strings.Builder
	cfg := &ssh.ClientConfig{
		User:            h.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // see README: known_hosts is future work
		Timeout:         dialTimeout,
		BannerCallback: func(msg string) error {
			banner.WriteString(msg)
			return nil
		},
	}
	addr := fmt.Sprintf("%s:%d", h.Address, h.DefaultPort())
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, "", classifyDial(err)
	}
	return conn, banner.String(), nil
}

func authMethods(h domain.Host, password string) ([]ssh.AuthMethod, error) {
	switch h.Auth {
	case domain.AuthKeyFile, domain.AuthNone:
		var methods []ssh.AuthMethod
		if h.AuthRef != "" {
			key, err := os.ReadFile(expandHome(h.AuthRef))
			if err != nil {
				return nil, domain.Fail(domain.CodeSecretUnavailable, "cannot read private key: "+err.Error())
			}
			var signer ssh.Signer
			if password != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(password))
			} else {
				signer, err = ssh.ParsePrivateKey(key)
			}
			if err != nil {
				return nil, domain.Fail(domain.CodeAuthFailed, "cannot parse private key: "+err.Error())
			}
			methods = append(methods, ssh.PublicKeys(signer))
		}
		if password != "" {
			methods = append(methods, ssh.Password(password))
		}
		if len(methods) == 0 {
			return nil, domain.Fail(domain.CodeSecretUnavailable, "no usable ssh credential: key path empty and no password")
		}
		return methods, nil
	default:
		// keyring/env/stdin all resolve to a password string upstream.
		if password == "" {
			return nil, domain.Fail(domain.CodeSecretUnavailable, "empty password for ssh password auth")
		}
		return []ssh.AuthMethod{ssh.Password(password)}, nil
	}
}

type client struct {
	conn   *ssh.Client
	banner string
}

func (c *client) Close() error {
	return c.conn.Close()
}

// Test opens a session channel and closes it: proves TCP + handshake + auth
// without executing anything.
func (c *client) Test(ctx context.Context) (domain.TestResult, error) {
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		sess, err := c.conn.NewSession()
		if err != nil {
			done <- err
			return
		}
		done <- sess.Close()
	}()
	select {
	case <-ctx.Done():
		c.conn.Close()
		<-done
		return domain.TestResult{}, domain.Fail(domain.CodeTimeout, "ssh handshake timed out")
	case err := <-done:
		if err != nil {
			return domain.TestResult{}, classifyDial(err)
		}
	}
	return domain.TestResult{Reachable: true, LatencyMs: time.Since(start).Milliseconds(), PreAuthBanner: c.banner}, nil
}

// Exec runs cmd exactly once with no PTY and no retry.
func (c *client) Exec(ctx context.Context, cmd string) (domain.ExecResult, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return domain.ExecResult{}, classifyDial(err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	type result struct {
		err error
	}
	done := make(chan result, 1)
	go func() { done <- result{sess.Run(cmd)} }()

	select {
	case <-ctx.Done():
		sess.Close()
		<-done
		return domain.ExecResult{PreAuthBanner: c.banner}, domain.Fail(domain.CodeTimeout, "ssh command timed out")
	case r := <-done:
		res := domain.ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), PreAuthBanner: c.banner}
		if r.err == nil {
			return res, nil
		}
		if ee, ok := r.err.(*ssh.ExitError); ok {
			res.ExitCode = ee.ExitStatus()
			return res, nil // remote failure is data, not a tool error
		}
		if ctx.Err() != nil {
			return res, domain.Fail(domain.CodeTimeout, "ssh command timed out")
		}
		return res, domain.Fail(domain.CodeConnectionFailed, "ssh command failed: "+r.err.Error())
	}
}

func classifyDial(err error) error {
	msg := err.Error()
	switch {
	case isAuthError(msg):
		return domain.Fail(domain.CodeAuthFailed, "ssh authentication failed: "+msg)
	case isTimeout(err, msg):
		return domain.Fail(domain.CodeTimeout, "ssh connection timed out: "+msg)
	default:
		return domain.Fail(domain.CodeConnectionFailed, "ssh connection failed: "+msg)
	}
}

func isAuthError(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "unable to authenticate") ||
		strings.Contains(m, "authentication failed") ||
		strings.Contains(m, "no supported methods") ||
		strings.Contains(m, "handshake failed")
}

func isTimeout(err error, msg string) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	m := strings.ToLower(msg)
	return strings.Contains(m, "timed out") || strings.Contains(m, "timeout") ||
		strings.Contains(m, "deadline exceeded")
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}
