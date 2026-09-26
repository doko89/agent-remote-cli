package sshmux

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"agent-remote/internal/domain"
)

type stubRunner struct {
	closed   atomic.Int32
	execs    atomic.Int32
	response domain.ExecResult
}

func (s *stubRunner) Test(context.Context) (domain.TestResult, error) {
	return domain.TestResult{Reachable: true}, nil
}

func (s *stubRunner) Exec(_ context.Context, cmd string) (domain.ExecResult, error) {
	s.execs.Add(1)
	return s.response, nil
}

func (s *stubRunner) Close() error { s.closed.Add(1); return nil }

func muxHost(name string) domain.Host {
	return domain.Host{Name: name, Protocol: domain.ProtocolSSH, Address: "h", User: "u"}
}

func TestMuxRoundTrip(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", filepath.Join(t.TempDir(), "hosts.json"))
	hub := NewHub()
	runner := &stubRunner{response: domain.ExecResult{Stdout: "hi\n", ExitCode: 0}}
	if err := hub.Offer(muxHost("a"), runner, "banner-x", DefaultTTL); err != nil {
		t.Fatal(err)
	}
	c := hub.TryDial(muxHost("a"))
	if c == nil {
		t.Fatal("TryDial must find the live master")
	}
	defer c.Close()
	res, err := c.Exec(context.Background(), "echo hi")
	if err != nil || res.Stdout != "hi\n" || res.ExitCode != 0 {
		t.Fatalf("exec: %+v %v", res, err)
	}
	if res.PreAuthBanner != "banner-x" {
		t.Fatalf("banner lost: %q", res.PreAuthBanner)
	}
	if runner.execs.Load() != 1 {
		t.Fatalf("exec count: %d", runner.execs.Load())
	}
	// Second client through the same master.
	c2 := hub.TryDial(muxHost("a"))
	if c2 == nil {
		t.Fatal("second TryDial must also find the master")
	}
	c2.Close()
}

func TestMuxNoMaster(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", filepath.Join(t.TempDir(), "hosts.json"))
	hub := NewHub()
	if hub.TryDial(muxHost("ghost")) != nil {
		t.Fatal("TryDial must return nil without a master")
	}
}

func TestMuxTTLExpiry(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", filepath.Join(t.TempDir(), "hosts.json"))
	hub := NewHub()
	runner := &stubRunner{}
	ttl := 400 * time.Millisecond
	if err := hub.Offer(muxHost("ttl"), runner, "", ttl); err != nil {
		t.Fatal(err)
	}
	if c := hub.TryDial(muxHost("ttl")); c == nil {
		t.Fatal("master must be reachable before TTL")
	} else {
		c.Close()
	}
	done := make(chan struct{})
	go func() { hub.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("hub.Wait did not return after TTL")
	}
	if runner.closed.Load() != 1 {
		t.Fatal("master must close the upstream client on expiry")
	}
}

func TestMuxStaleSocketRecovered(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", filepath.Join(t.TempDir(), "hosts.json"))
	dir, err := defaultDir()
	if err != nil {
		t.Skip("no home dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skip(err)
	}
	stale := socketPath(dir, muxHost("stale"))
	os.Remove(stale)
	// Bind and close: the file remains but nothing listens.
	ln, err := net.Listen("unix", stale)
	if err != nil {
		t.Skip("cannot bind test socket")
	}
	ln.Close()

	hub := NewHub()
	if err := hub.Offer(muxHost("stale"), &stubRunner{}, "", 300*time.Millisecond); err != nil {
		t.Fatalf("stale socket must be recovered, got %v", err)
	}
	hub.Wait()
}

// TestMuxStaleSocketRemovedOnTryDial proves TryDial deletes a dead master's
// socket file so Offer never trips over stale debris.
func TestMuxStaleSocketRemovedOnTryDial(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", filepath.Join(t.TempDir(), "hosts.json"))
	dir, err := defaultDir()
	if err != nil {
		t.Skip(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Skip(err)
	}
	path := socketPath(dir, muxHost("dead"))
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skip(err)
	}
	ln.Close() // file remains, no listener

	hub := NewHub()
	if c := hub.TryDial(muxHost("dead")); c != nil {
		t.Fatal("TryDial must return nil for a dead socket")
	}
	_, statErr := os.Stat(path)
	if !os.IsNotExist(statErr) {
		t.Fatal("stale socket file must be removed")
	}
}

// TestMuxErrorSentPhases pins the retry-safety boundary: dial failure means
// nothing was sent (safe to re-run on a fresh connection).
func TestMuxErrorSentPhases(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", filepath.Join(t.TempDir(), "hosts.json"))
	c := &muxClient{path: filepath.Join(t.TempDir(), "nope.sock")}
	_, err := c.round(context.Background(), request{Command: "x"})
	var me *MuxError
	if err == nil || !errors.As(err, &me) {
		t.Fatalf("round must return MuxError, got %v", err)
	}
	if me.Sent {
		t.Fatal("dial failure must be Sent=false")
	}
}

func TestMuxMasterAliveRejected(t *testing.T) {
	t.Setenv("AGENT_REMOTE_CONFIG", filepath.Join(t.TempDir(), "hosts.json"))
	hub := NewHub()
	if err := hub.Offer(muxHost("two"), &stubRunner{}, "", 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	err := hub.Offer(muxHost("two"), &stubRunner{}, "", DefaultTTL)
	if err == nil || err.Error() != ErrMasterAlive.Error() {
		t.Fatalf("second offer must report alive, got %v", err)
	}
	hub.Wait()
}
