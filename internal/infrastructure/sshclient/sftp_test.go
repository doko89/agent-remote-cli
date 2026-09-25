package sshclient

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agent-remote/internal/domain"
)

func sftpHost(t *testing.T, srv *testServer) domain.Host {
	t.Helper()
	return domain.Host{
		Name: "t", Protocol: domain.ProtocolSSH, Address: "127.0.0.1",
		Port: srv.listener.Addr().(*net.TCPAddr).Port,
		User: "tester", Auth: domain.AuthEnv, AuthRef: "PW",
		Filter: domain.DefaultFilter(),
	}
}

// TestSFTPTransferRoundTrip exercises the SFTP client against the in-process
// server: upload in chunks, stat, chunked read, listing, and parents.
func TestSFTPTransferRoundTrip(t *testing.T) {
	srv := startTestServer(t)
	dir := t.TempDir()
	c, err := (SFTPFactory{}).NewTransferClient(sftpHost(t, srv), "s3cret")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ctx := ctxTimeout(t, 10*time.Second)

	remote := filepath.Join(dir, "sub", "f.bin")
	payload := make([]byte, 300*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := c.MkdirAll(ctx, filepath.Join(dir, "sub")); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const chunk = 100 * 1024
	for i, first := 0, true; i < len(payload); i, first = i+chunk, false {
		end := i + chunk
		if end > len(payload) {
			end = len(payload)
		}
		if err := c.AppendChunk(ctx, remote, payload[i:end], first); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	fi, err := c.Stat(ctx, remote)
	if err != nil || fi.IsDir || fi.Size != int64(len(payload)) {
		t.Fatalf("stat: %+v %v", fi, err)
	}
	var got []byte
	for off := int64(0); ; {
		b, err := c.ReadAt(ctx, remote, off, chunk)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(b) == 0 {
			break
		}
		got = append(got, b...)
		off += int64(len(b))
	}
	if string(got) != string(payload) {
		t.Fatal("round-trip content mismatch")
	}
	entries, err := c.ReadDir(ctx, filepath.Join(dir, "sub"))
	if err != nil || len(entries) != 1 || entries[0].Path != remote {
		t.Fatalf("readdir: %+v %v", entries, err)
	}
	if c.Parent(remote) != filepath.Join(dir, "sub") {
		t.Fatalf("parent: %q", c.Parent(remote))
	}
	if err := c.Finalize(ctx, remote); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, err := c.Stat(ctx, filepath.Join(dir, "nope")); err == nil {
		t.Fatal("missing must fail")
	}
	if _, err := os.Stat(remote); err != nil {
		t.Fatalf("server side missing: %v", err)
	}
}
