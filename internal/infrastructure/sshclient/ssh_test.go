package sshclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"agent-remote/internal/domain"
)

// testServer is a minimal in-process SSH server. It records whether the
// client ever requested a PTY (it must not: Lapis 1) and serves canned
// command output including a banner line.
type testServer struct {
	listener net.Listener
	sawPty   bool
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == "tester" && string(password) == "s3cret" {
				return nil, nil
			}
			return nil, fmt.Errorf("bad credentials")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "tester" {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown user")
		},
		BannerCallback: func(conn ssh.ConnMetadata) string {
			return "Authorized users only\n"
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{listener: ln}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *testServer) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		nc.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "test server: session only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}
		go s.serveSession(channel, requests)
	}
	conn.Wait()
}

// serveSession answers pty/exec/subsystem requests on one session channel.
func (s *testServer) serveSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "pty-req":
			s.sawPty = true
			req.Reply(false, nil)
		case "exec":
			s.serveExec(channel, req)
		case "subsystem":
			var payload struct{ Value string }
			ssh.Unmarshal(req.Payload, &payload)
			if payload.Value != "sftp" {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			srv, err := sftp.NewServer(channel)
			if err != nil {
				return
			}
			// The channel now belongs to the SFTP server; close it when
			// done so the client side terminates instead of hanging.
			_ = srv.Serve()
			channel.Close()
			return
		default:
			req.Reply(false, nil)
		}
	}
}

// serveExec runs one canned command and closes the channel.
func (s *testServer) serveExec(channel ssh.Channel, req *ssh.Request) {
	var payload struct{ Value string }
	ssh.Unmarshal(req.Payload, &payload)
	req.Reply(true, nil)
	if payload.Value == "sleep" {
		time.Sleep(3 * time.Second)
		fmt.Fprint(channel, "late\n")
		s.exit(channel, 0)
		return
	}
	stdout, stderr, code := "Last login: today\nok\n", "", 0
	if payload.Value == "fail" {
		stdout, stderr, code = "Last login: today\npartial\n", "boom\n", 3
	}
	fmt.Fprint(channel, stdout)
	fmt.Fprint(channel.Stderr(), stderr)
	s.exit(channel, code)
}

func (s *testServer) exit(channel ssh.Channel, code int) {
	channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
	channel.Close()
}

func testHost(port int) domain.Host {
	return domain.Host{
		Name: "t", Protocol: domain.ProtocolSSH, Address: "127.0.0.1",
		Port: port, User: "tester", Auth: domain.AuthEnv, AuthRef: "PW",
		Filter: domain.DefaultFilter(),
	}
}

func TestExecCapturesBannerSeparately(t *testing.T) {
	srv := startTestServer(t)
	f := Factory{}
	c, err := f.NewClient(testHost(srv.listener.Addr().(*net.TCPAddr).Port), "s3cret")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	res, err := c.Exec(ctxTimeout(t, 5*time.Second), "hello")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d", res.ExitCode)
	}
	// Raw client output still carries the MOTD line (Lapis-2 filtering is
	// the use-case layer's job); it must not be silently dropped here.
	if res.Stdout != "Last login: today\nok\n" {
		t.Fatalf("unexpected stdout: %q", res.Stdout)
	}
	if res.PreAuthBanner != "Authorized users only\n" {
		t.Fatalf("pre-auth banner leaked or lost: %q", res.PreAuthBanner)
	}
	if srv.sawPty {
		t.Fatal("client requested a PTY; Lapis-1 requires no PTY")
	}
}

func TestExecRemoteFailureIsData(t *testing.T) {
	srv := startTestServer(t)
	f := Factory{}
	c, err := f.NewClient(testHost(srv.listener.Addr().(*net.TCPAddr).Port), "s3cret")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	res, err := c.Exec(ctxTimeout(t, 5*time.Second), "fail")
	if err != nil {
		t.Fatalf("remote failure must not be a tool error: %v", err)
	}
	if res.ExitCode != 3 || res.Stdout != "Last login: today\npartial\n" || res.Stderr != "boom\n" {
		t.Fatalf("wrong result: %+v", res)
	}
}

func TestAuthFailureClassified(t *testing.T) {
	srv := startTestServer(t)
	f := Factory{}
	if _, err := f.NewClient(testHost(srv.listener.Addr().(*net.TCPAddr).Port), "wrong"); err == nil {
		t.Fatal("expected auth failure")
	} else if domain.CodeOf(err) != domain.CodeAuthFailed {
		t.Fatalf("expected auth_failed, got %q (%v)", domain.CodeOf(err), err)
	}
}

func TestKeyFileAuth(t *testing.T) {
	srv := startTestServer(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	keyPath := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	h := testHost(srv.listener.Addr().(*net.TCPAddr).Port)
	h.Auth = domain.AuthKeyFile
	h.AuthRef = keyPath
	f := Factory{}
	c, err := f.NewClient(h, "")
	if err != nil {
		t.Fatalf("key auth dial: %v", err)
	}
	defer c.Close()
	res, err := c.Exec(ctxTimeout(t, 5*time.Second), "hello")
	if err != nil || res.Stdout != "Last login: today\nok\n" {
		t.Fatalf("got %+v %v", res, err)
	}
}

func TestExecTimeoutClassified(t *testing.T) {
	srv := startTestServer(t)
	f := Factory{}
	c, err := f.NewClient(testHost(srv.listener.Addr().(*net.TCPAddr).Port), "s3cret")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Exec(ctxTimeout(t, 200*time.Millisecond), "sleep"); domain.CodeOf(err) != domain.CodeTimeout {
		t.Fatalf("expected timeout, got %v", err)
	}
}

func TestClassifyDial(t *testing.T) {
	if domain.CodeOf(classifyDial(errTimeout{})) != domain.CodeTimeout {
		t.Fatal("net timeout must map to timeout")
	}
	if domain.CodeOf(classifyDial(fmt.Errorf("ssh: handshake failed: unable to authenticate"))) != domain.CodeAuthFailed {
		t.Fatal("auth message must map to auth_failed")
	}
	if domain.CodeOf(classifyDial(fmt.Errorf("connection refused"))) != domain.CodeConnectionFailed {
		t.Fatal("other errors must map to connection_failed")
	}
}

type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }

func TestKeyFileErrors(t *testing.T) {
	f := Factory{}
	h := testHost(22)
	h.Auth = domain.AuthKeyFile
	h.AuthRef = filepath.Join(t.TempDir(), "missing")
	if _, err := f.NewClient(h, ""); domain.CodeOf(err) != domain.CodeSecretUnavailable {
		t.Fatalf("missing key must be secret_unavailable, got %v", err)
	}
	h.AuthRef = ""
	if _, err := f.NewClient(h, ""); err == nil {
		t.Fatal("keyfile without path and without password must fail")
	}
}

func TestHandshakeOnly(t *testing.T) {
	srv := startTestServer(t)
	f := Factory{}
	c, err := f.NewClient(testHost(srv.listener.Addr().(*net.TCPAddr).Port), "s3cret")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	res, err := c.Test(ctxTimeout(t, 5*time.Second))
	if err != nil || !res.Reachable {
		t.Fatalf("test failed: %+v %v", res, err)
	}
	if srv.sawPty {
		t.Fatal("Test must not request a PTY")
	}
}
