package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

type fakeTClient struct {
	files  map[string][]byte
	mtimes map[string]time.Time
	dirs   map[string]bool
}

func (f *fakeTClient) Stat(_ context.Context, p string) (usecase.RemoteFile, error) {
	if f.dirs[p] {
		return usecase.RemoteFile{Path: p, IsDir: true}, nil
	}
	if b, ok := f.files[p]; ok {
		return usecase.RemoteFile{Path: p, Size: int64(len(b)), ModTime: f.mtimes[p]}, nil
	}
	return usecase.RemoteFile{}, domain.Fail(domain.CodeInvalidInput, "no such file")
}

func (f *fakeTClient) Remove(_ context.Context, p string) error {
	delete(f.files, p)
	delete(f.mtimes, p)
	delete(f.dirs, p)
	return nil
}

func (f *fakeTClient) SetMTime(_ context.Context, p string, mt time.Time) error {
	if f.mtimes == nil {
		f.mtimes = map[string]time.Time{}
	}
	f.mtimes[p] = mt
	return nil
}

func (f *fakeTClient) ReadDir(_ context.Context, p string) ([]usecase.RemoteFile, error) {
	var out []usecase.RemoteFile
	for fp, b := range f.files {
		if filepath.Dir(fp) == p {
			out = append(out, usecase.RemoteFile{Path: fp, Size: int64(len(b)), ModTime: f.mtimes[fp]})
		}
	}
	return out, nil
}

func (f *fakeTClient) MkdirAll(_ context.Context, p string) error {
	f.dirs[p] = true
	return nil
}

func (f *fakeTClient) ReadAt(_ context.Context, p string, offset int64, n int) ([]byte, error) {
	b := f.files[p]
	if int(offset) >= len(b) {
		return nil, nil
	}
	end := int(offset) + n
	if end > len(b) {
		end = len(b)
	}
	return b[offset:end], nil
}

func (f *fakeTClient) AppendChunk(_ context.Context, p string, data []byte, first bool) error {
	if first {
		f.files[p] = nil
	}
	f.files[p] = append(f.files[p], data...)
	return nil
}

func (f *fakeTClient) Parent(p string) string { return filepath.Dir(p) }

func (f *fakeTClient) Finalize(_ context.Context, _ string) error { return nil }
func (f *fakeTClient) Close() error                               { return nil }

type fakeTFactory struct{ remote *fakeTClient }

func (f fakeTFactory) NewTransferClient(domain.Host, string) (usecase.TransferClient, error) {
	return f.remote, nil
}

func cpDeps(remote *fakeTClient) Deps {
	d := testDeps()
	d.TFactory = fakeTFactory{remote}
	return d
}

func TestCpRefErrors(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	for _, args := range [][]string{
		{"cp", "a", "b", "c"},
		{"cp", "a"},
		{"cp", "nope:/x", "/tmp/y"},
		{"cp", "h:", "/tmp/y"},
		{"cp", "/tmp/x", "/tmp/y"},
	} {
		if out, _ := Run(args, opt, deps); out.ToolErr == nil {
			t.Fatalf("%v: expected error", args)
		}
	}
}

func TestCpLocalToRemote(t *testing.T) {
	remote := &fakeTClient{files: map[string][]byte{}, dirs: map[string]bool{}}
	deps := cpDeps(remote)
	opt := Options{Version: "test"}
	if out, _ := Run([]string{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "stdin"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("add: %v", out.ToolErr)
	}
	src := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(src, []byte("cp-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := Run([]string{"cp", src, "h:/r/f.txt"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("cp: %v", out.ToolErr)
	}
	if string(remote.files["/r/f.txt"]) != "cp-data" {
		t.Fatalf("content: %q", remote.files)
	}
	if out.ExitCode() != ExitOK || !strings.Contains(out.RawOut, "1 file(s)") {
		t.Fatalf("outcome: %+v", out)
	}
}

func TestCpHelp(t *testing.T) {
	if out, _ := Run([]string{"cp", "--help"}, Options{Version: "t"}, testDeps()); out.ToolErr != nil || out.RawOut == "" {
		t.Fatalf("cp help: %+v", out)
	}
}
