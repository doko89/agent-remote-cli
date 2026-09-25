package usecase

import (
	"context"
	"testing"
	"time"

	"agent-remote/internal/domain"
)

func syncStore() *memStore {
	return &memStore{hosts: map[string]domain.Host{
		"r1": {Name: "r1", Protocol: domain.ProtocolSSH, Address: "a", User: "u", Auth: domain.AuthNone},
		"r2": {Name: "r2", Protocol: domain.ProtocolWinRM, Address: "b", User: "u", Auth: domain.AuthNone},
	}}
}

func syncFactory(r1, r2 *memRemote) memTFactory {
	return memTFactory{remotes: map[string]*memRemote{"r1": r1, "r2": r2}}
}

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Hour)
)

// fixture builds src with: same.txt (identical), chg.txt (newer+other size),
// new.txt (missing on dst); dst with those plus extra.txt and extra/ dir.
func syncFixture() (*memRemote, *memRemote) {
	src := newMemRemote()
	src.dirs["/s"] = true
	src.files["/s/same.txt"] = []byte("same")
	src.mtimes["/s/same.txt"] = t0
	src.files["/s/chg.txt"] = []byte("v2-longer")
	src.mtimes["/s/chg.txt"] = t1
	src.files["/s/new.txt"] = []byte("new")
	src.mtimes["/s/new.txt"] = t1
	src.dirs["/s/sub"] = true

	dst := newMemRemote()
	dst.files["/d/same.txt"] = []byte("same")
	dst.mtimes["/d/same.txt"] = t0
	dst.files["/d/chg.txt"] = []byte("v1")
	dst.mtimes["/d/chg.txt"] = t0
	dst.files["/d/extra.txt"] = []byte("extra")
	dst.mtimes["/d/extra.txt"] = t0
	dst.dirs["/d"] = true
	dst.dirs["/d/extra"] = true
	return src, dst
}

func TestSyncHalfSideSkipsFreshKeepsExtra(t *testing.T) {
	src, dst := syncFixture()
	factory := syncFactory(src, dst)
	var events []SyncEvent
	res, err := SyncOneShot(context.Background(), syncStore(), stubSecrets{}, factory,
		SyncRequest{SrcHost: "r1", SrcPath: "/s", DstHost: "r2", DstPath: "/d",
			Opt: SyncOptions{OnEvent: func(e SyncEvent) { events = append(events, e) }}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || res.Deleted != 0 {
		t.Fatalf("half side must copy 2, delete 0: %+v", res)
	}
	if string(dst.files["/d/chg.txt"]) != "v2-longer" || string(dst.files["/d/new.txt"]) != "new" {
		t.Fatalf("copies wrong: %v", dst.files)
	}
	if _, ok := dst.files["/d/extra.txt"]; !ok {
		t.Fatal("half side must keep extras")
	}
	if _, ok := dst.dirs["/d/extra"]; !ok {
		t.Fatal("half side must keep extra dirs")
	}
	if !dst.mtimes["/d/new.txt"].Equal(t1) {
		t.Fatalf("mtime not stamped: %v", dst.mtimes["/d/new.txt"])
	}
	if len(events) != 3 { // 2 copies + 1 mkdir(sub)
		t.Fatalf("events: %+v", events)
	}
	// Second scan is a no-op: everything fresh now.
	res2, err := SyncOneShot(context.Background(), syncStore(), stubSecrets{}, factory,
		SyncRequest{SrcHost: "r1", SrcPath: "/s", DstHost: "r2", DstPath: "/d"})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Files != 0 || res2.Bytes != 0 {
		t.Fatalf("second scan must be quiet: %+v", res2)
	}
}

func TestSyncEverythingDeletes(t *testing.T) {
	src, dst := syncFixture()
	factory := syncFactory(src, dst)
	res, err := SyncOneShot(context.Background(), syncStore(), stubSecrets{}, factory,
		SyncRequest{SrcHost: "r1", SrcPath: "/s", DstHost: "r2", DstPath: "/d",
			Opt: SyncOptions{Delete: true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 2 { // extra.txt + extra/
		t.Fatalf("expected 2 deletes: %+v", res)
	}
	if _, ok := dst.files["/d/extra.txt"]; ok {
		t.Fatal("extra file survived")
	}
	if dst.dirs["/d/extra"] {
		t.Fatal("extra dir survived")
	}
}

func TestSyncSingleFileAndLocal(t *testing.T) {
	src := newMemRemote()
	src.files["/s/one.txt"] = []byte("1")
	src.mtimes["/s/one.txt"] = t1
	factory := syncFactory(src, newMemRemote())
	dst := t.TempDir() + "/one.txt"
	res, err := SyncOneShot(context.Background(), syncStore(), stubSecrets{}, factory,
		SyncRequest{SrcHost: "r1", SrcPath: "/s/one.txt", DstPath: dst})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 1 || mustRead(t, dst) != "1" {
		t.Fatalf("got %+v", res)
	}
	// Re-sync is quiet.
	res, err = SyncOneShot(context.Background(), syncStore(), stubSecrets{}, factory,
		SyncRequest{SrcHost: "r1", SrcPath: "/s/one.txt", DstPath: dst})
	if err != nil || res.Files != 0 {
		t.Fatalf("re-sync must skip: %+v %v", res, err)
	}
}

func TestSyncRejects(t *testing.T) {
	factory := syncFactory(newMemRemote(), newMemRemote())
	for name, req := range map[string]SyncRequest{
		"local-local": {SrcPath: "/a", DstPath: "/b"},
		"empty":       {SrcHost: "r1", DstHost: "r2"},
		"same":        {SrcHost: "r1", SrcPath: "/x", DstHost: "r1", DstPath: "/x"},
		"unknown":     {SrcHost: "nope", SrcPath: "/x", DstHost: "r2", DstPath: "/y"},
		"missing-src": {SrcHost: "r1", SrcPath: "/nope", DstHost: "r2", DstPath: "/y"},
	} {
		if _, err := SyncOneShot(context.Background(), syncStore(), stubSecrets{}, factory, req); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

// TestWatchCopiesOnChange proves the watch loop picks up a change made
// after an earlier scan. Everything runs on Watch's own goroutine (the hook
// mutates and cancels), so the test is deterministic with no sleeps.
func TestWatchCopiesOnChange(t *testing.T) {
	src := newMemRemote()
	src.dirs["/s"] = true
	src.files["/s/a.txt"] = []byte("v1")
	src.mtimes["/s/a.txt"] = t0
	dst := newMemRemote()
	factory := syncFactory(src, dst)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	copies := 0
	total, err := Watch(ctx, syncStore(), stubSecrets{}, factory,
		SyncRequest{SrcHost: "r1", SrcPath: "/s", DstHost: "r2", DstPath: "/d"},
		10*time.Millisecond, func(e SyncEvent) {
			if e.Op != "copy" {
				return
			}
			copies++
			if copies == 1 {
				src.files["/s/a.txt"] = []byte("v2!")
				src.mtimes["/s/a.txt"] = t1
			}
			if copies == 2 {
				cancel()
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	if copies != 2 || total.Scans < 2 || total.Files != 2 {
		t.Fatalf("copies=%d total=%+v", copies, total)
	}
	if string(dst.files["/d/a.txt"]) != "v2!" {
		t.Fatalf("change not picked up: %v", dst.files)
	}
}
