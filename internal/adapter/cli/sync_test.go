package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func syncDeps(t *testing.T) (Deps, Options) {
	t.Helper()
	deps := cpDeps(&fakeTClient{files: map[string][]byte{}, dirs: map[string]bool{}})
	opt := Options{Version: "test"}
	if out, _ := Run([]string{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "stdin"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("add: %v", out.ToolErr)
	}
	return deps, opt
}

func remoteOf(deps Deps) *fakeTClient {
	return deps.TFactory.(fakeTFactory).remote
}

func TestSyncOneShotHalf(t *testing.T) {
	deps, opt := syncDeps(t)
	src := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(src, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _ := Run([]string{"sync", src, "h:/d/s.txt"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("sync: %v", out.ToolErr)
	}
	data := out.Data.(map[string]any)
	if data["mode"] != "half" || data["files"] != int64(1) {
		t.Fatalf("data: %v", data)
	}
	if string(remoteOf(deps).files["/d/s.txt"]) != "v1" {
		t.Fatal("not copied")
	}
	// Quiet re-sync.
	out, _ = Run([]string{"sync", src, "h:/d/s.txt"}, opt, deps)
	if out.ToolErr != nil || out.Data.(map[string]any)["files"] != int64(0) {
		t.Fatalf("re-sync: %+v", out)
	}
}

func TestSyncEverythingDeletes(t *testing.T) {
	deps, opt := syncDeps(t)
	r := remoteOf(deps)
	r.files["/d/extra.txt"] = []byte("x")
	r.dirs["/d"] = true
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Half side keeps the extra.
	if out, _ := Run([]string{"sync", srcDir, "h:/d"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("sync: %v", out.ToolErr)
	}
	if _, ok := r.files["/d/extra.txt"]; !ok {
		t.Fatal("half side must keep extras")
	}
	// Everything mode removes it.
	out, _ := Run([]string{"sync", "--delete", srcDir, "h:/d"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("sync --delete: %v", out.ToolErr)
	}
	if _, ok := r.files["/d/extra.txt"]; ok {
		t.Fatal("everything must delete extras")
	}
	if out.Data.(map[string]any)["deleted"] != int64(1) || out.Data.(map[string]any)["mode"] != "everything" {
		t.Fatalf("data: %v", out.Data)
	}
}

func TestSyncFlagErrors(t *testing.T) {
	deps, opt := syncDeps(t)
	for _, args := range [][]string{
		{"sync", "--delete", "--half", "a", "b"},
		{"sync", "a"},
		{"sync", "--timeout", "0s", "a", "b"},
		{"sync", "-w", "--interval", "0s", "a", "b"},
		{"sync", "nope:/x", "h:/y"},
	} {
		if out, _ := Run(args, opt, deps); out.ToolErr == nil {
			t.Fatalf("%v: expected error", args)
		}
	}
	if out, _ := Run([]string{"sync", "--help"}, opt, deps); out.ToolErr != nil || out.RawOut == "" {
		t.Fatalf("help: %+v", out)
	}
}
