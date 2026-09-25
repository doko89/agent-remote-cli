package usecase

import (
	"context"
	"errors"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"agent-remote/internal/domain"
)

// memRemote is an in-memory TransferClient: files live in a map, dirs in a
// set, separators are "/". It proves Copy orchestration (streaming, counts,
// recursion, relay) without any network.
type memRemote struct {
	files map[string][]byte
	dirs  map[string]bool
}

func newMemRemote() *memRemote {
	return &memRemote{files: map[string][]byte{}, dirs: map[string]bool{"/": true}}
}

func (m *memRemote) Stat(_ context.Context, p string) (RemoteFile, error) {
	if m.dirs[p] {
		return RemoteFile{Path: p, IsDir: true}, nil
	}
	if b, ok := m.files[p]; ok {
		return RemoteFile{Path: p, Size: int64(len(b))}, nil
	}
	return RemoteFile{}, domain.Fail(domain.CodeInvalidInput, "no such file")
}

func (m *memRemote) ReadDir(_ context.Context, p string) ([]RemoteFile, error) {
	if !m.dirs[p] {
		return nil, domain.Fail(domain.CodeInvalidInput, "no such dir")
	}
	seen := map[string]RemoteFile{}
	prefix := strings.TrimSuffix(p, "/") + "/"
	for f, b := range m.files {
		if !strings.HasPrefix(f, prefix) {
			continue
		}
		rest := strings.TrimPrefix(f, prefix)
		if i := strings.Index(rest, "/"); i >= 0 {
			seen[prefix+rest[:i]] = RemoteFile{Path: prefix + rest[:i], IsDir: true}
		} else {
			seen[f] = RemoteFile{Path: f, Size: int64(len(b))}
		}
	}
	for d := range m.dirs {
		if d != p && strings.HasPrefix(d, prefix) {
			rest := strings.TrimPrefix(d, prefix)
			if !strings.Contains(strings.TrimSuffix(rest, "/"), "/") {
				seen[d] = RemoteFile{Path: d, IsDir: true}
			}
		}
	}
	out := make([]RemoteFile, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (m *memRemote) MkdirAll(_ context.Context, p string) error {
	for cur := p; cur != "" && cur != "/"; cur = path.Dir(cur) {
		m.dirs[cur] = true
	}
	m.dirs["/"] = true
	return nil
}

func (m *memRemote) ReadAt(_ context.Context, p string, offset int64, n int) ([]byte, error) {
	b, ok := m.files[p]
	if !ok {
		return nil, domain.Fail(domain.CodeInvalidInput, "no such file")
	}
	if offset >= int64(len(b)) {
		return nil, nil
	}
	end := offset + int64(n)
	if end > int64(len(b)) {
		end = int64(len(b))
	}
	return b[offset:end], nil
}

func (m *memRemote) AppendChunk(_ context.Context, p string, data []byte, first bool) error {
	if first {
		m.files[p] = nil
	}
	m.files[p] = append(m.files[p], data...)
	return nil
}

func (m *memRemote) Parent(p string) string { return path.Dir(p) }

func (m *memRemote) Finalize(_ context.Context, _ string) error { return nil }
func (m *memRemote) Close() error                               { return nil }

type memTFactory struct{ remotes map[string]*memRemote }

func (f memTFactory) NewTransferClient(h domain.Host, _ string) (TransferClient, error) {
	r, ok := f.remotes[h.Name]
	if !ok || r == nil {
		return nil, errors.New("no such remote")
	}
	return r, nil
}

func cpStore() *memStore {
	return &memStore{hosts: map[string]domain.Host{
		"r1": {Name: "r1", Protocol: domain.ProtocolSSH, Address: "a", User: "u", Auth: domain.AuthNone},
		"r2": {Name: "r2", Protocol: domain.ProtocolWinRM, Address: "b", User: "u", Auth: domain.AuthNone},
	}}
}

func TestCopyLocalToRemote(t *testing.T) {
	store := cpStore()
	r1 := newMemRemote()
	factory := memTFactory{remotes: map[string]*memRemote{"r1": r1}}
	src := t.TempDir() + "/hello.txt"
	mustWrite(t, src, "hello remote\n")
	res, err := Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "", SrcPath: src, DstHost: "r1", DstPath: "/up/hello.txt", Opt: CopyOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || res.Bytes != 13 {
		t.Fatalf("counts wrong: %+v", res)
	}
	if string(r1.files["/up/hello.txt"]) != "hello remote\n" {
		t.Fatalf("content wrong: %q", r1.files["/up/hello.txt"])
	}
}

func TestCopyRemoteToLocal(t *testing.T) {
	store := cpStore()
	r1 := newMemRemote()
	r1.files["/down/data.bin"] = []byte("0123456789")
	factory := memTFactory{remotes: map[string]*memRemote{"r1": r1}}
	dst := t.TempDir() + "/sub/data.bin"
	res, err := Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "r1", SrcPath: "/down/data.bin", DstHost: "", DstPath: dst, Opt: CopyOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || res.Bytes != 10 {
		t.Fatalf("counts wrong: %+v", res)
	}
	if mustRead(t, dst) != "0123456789" {
		t.Fatalf("content wrong: %q", mustRead(t, dst))
	}
}

func TestCopyRecursiveBothWays(t *testing.T) {
	store := cpStore()
	r1 := newMemRemote()
	factory := memTFactory{remotes: map[string]*memRemote{"r1": r1, "r2": newMemRemote()}}
	base := t.TempDir()
	mustWrite(t, base+"/tree/a.txt", "aaa")
	mustWrite(t, base+"/tree/sub/b.txt", "bb")
	if err := os.MkdirAll(base+"/tree/emptydir", 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "", SrcPath: base + "/tree", DstHost: "r1", DstPath: "/rtree", Opt: CopyOptions{Recursive: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || res.Bytes != 5 {
		t.Fatalf("up counts wrong: %+v", res)
	}
	if string(r1.files["/rtree/a.txt"]) != "aaa" || string(r1.files["/rtree/sub/b.txt"]) != "bb" {
		t.Fatalf("tree wrong: %v", r1.files)
	}
	if !r1.dirs["/rtree/emptydir"] {
		t.Fatal("empty dir not created")
	}
	out := t.TempDir() + "/back"
	res, err = Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "r1", SrcPath: "/rtree", DstHost: "", DstPath: out, Opt: CopyOptions{Recursive: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || mustRead(t, out+"/sub/b.txt") != "bb" {
		t.Fatalf("down wrong: %+v", res)
	}
}

func TestCopyRemoteToRemoteRelay(t *testing.T) {
	store := cpStore()
	r1 := newMemRemote()
	r1.files["/x/f.txt"] = []byte("relay-me")
	factory := memTFactory{remotes: map[string]*memRemote{"r1": r1, "r2": newMemRemote()}}
	res, err := Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "r1", SrcPath: "/x/f.txt", DstHost: "r2", DstPath: "/y/f.txt", Opt: CopyOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || res.Bytes != 8 {
		t.Fatalf("counts wrong: %+v", res)
	}
	if string(factory.remotes["r2"].files["/y/f.txt"]) != "relay-me" {
		t.Fatal("relay content lost")
	}
	// Relay refuses directories without -r, and stages trees with it.
	r1.dirs["/x"] = true // now /x is a real dir containing f.txt
	if _, err := Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "r1", SrcPath: "/x", DstHost: "r2", DstPath: "/z", Opt: CopyOptions{}}); err == nil {
		t.Fatal("relay dir without -r must fail")
	}
	res, err = Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "r1", SrcPath: "/x", DstHost: "r2", DstPath: "/z", Opt: CopyOptions{Recursive: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || string(factory.remotes["r2"].files["/z/f.txt"]) != "relay-me" {
		t.Fatalf("relay tree wrong: %+v", res)
	}
}

func TestCopyEmptyFile(t *testing.T) {
	store := cpStore()
	r1 := newMemRemote()
	factory := memTFactory{remotes: map[string]*memRemote{"r1": r1}}
	src := t.TempDir() + "/empty.txt"
	mustWrite(t, src, "")
	res, err := Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: "", SrcPath: src, DstHost: "r1", DstPath: "/empty.txt", Opt: CopyOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || res.Bytes != 0 {
		t.Fatalf("counts wrong: %+v", res)
	}
	b, ok := r1.files["/empty.txt"]
	if !ok || len(b) != 0 {
		t.Fatalf("empty file not materialized: %v", r1.files)
	}
}

func TestCopyRejects(t *testing.T) {
	store := cpStore()
	factory := memTFactory{remotes: map[string]*memRemote{"r1": newMemRemote()}}
	cases := []struct {
		name       string
		srcH, srcP string
		dstH, dstP string
		recursive  bool
	}{
		{"local-local", "", "/a", "", "/b", false},
		{"empty-path", "", "", "r1", "/b", false},
		{"same", "r1", "/a", "r1", "/a", false},
		{"unknown-host", "nope", "/a", "", "/tmp/x", false},
		{"dir-no-recursive", "", t.TempDir(), "r1", "/d", false},
		{"missing-remote", "r1", "/nope", "", t.TempDir() + "/x", false},
	}
	for _, tc := range cases {
		if _, err := Copy(context.Background(), store, stubSecrets{}, factory, CopyRequest{SrcHost: tc.srcH, SrcPath: tc.srcP, DstHost: tc.dstH, DstPath: tc.dstP, Opt: CopyOptions{Recursive: tc.recursive}}); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(dirOf(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func dirOf(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}
