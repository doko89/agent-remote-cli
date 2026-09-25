package winrmclient

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"agent-remote/internal/usecase"
)

func TestPsQuote(t *testing.T) {
	if got := psQuote(`C:\temp\a'b`); got != `'C:\temp\a''b'` {
		t.Fatalf("got %s", got)
	}
	if got := psQuote("plain"); got != "'plain'" {
		t.Fatalf("got %s", got)
	}
}

func TestWinParent(t *testing.T) {
	for in, want := range map[string]string{
		`C:\temp\file.txt`: `C:\temp`,
		`C:/temp/file.txt`: `C:/temp`,
		`C:\temp\`:         `C:`,
		`C:`:               `C:`,
	} {
		if got := winParent(in); got != want {
			t.Fatalf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestSplitB64(t *testing.T) {
	parts := splitB64("abcdefghij", 4)
	if len(parts) != 3 || parts[0] != "abcd" || parts[2] != "ij" {
		t.Fatalf("got %v", parts)
	}
	if len(splitB64("", 4)) != 0 {
		t.Fatal("empty must stay empty")
	}
}

func TestParseDirJSON(t *testing.T) {
	if got, err := parseDirJSON(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	one, err := parseDirJSON(`{"name":"a.txt","is_container":false,"length":5}`)
	if err != nil || len(one) != 1 || one[0].Name != "a.txt" || *one[0].Length != 5 {
		t.Fatalf("single: %+v %v", one, err)
	}
	many, err := parseDirJSON(`[{"name":"d","is_container":true,"length":null},{"name":"f","is_container":false,"length":3}]`)
	if err != nil || len(many) != 2 || !many[0].IsContainer || many[1].Length == nil {
		t.Fatalf("array: %+v %v", many, err)
	}
	if _, err := parseDirJSON("{oops"); err == nil {
		t.Fatal("corrupt must fail")
	}
}

// scriptInner records PowerShell fragments and replays canned outputs.
// Unmatched fragments succeed empty, so tests only script what matters.
type scriptInner struct {
	scripts []string
	replies map[string]scriptReply
}

type scriptReply struct {
	stdout string
	stderr string
	code   int
	err    error
}

func (s *scriptInner) RunPSWithContext(_ context.Context, cmd string) (string, string, int, error) {
	s.scripts = append(s.scripts, cmd)
	for match, r := range s.replies {
		if strings.Contains(cmd, match) {
			return r.stdout, r.stderr, r.code, r.err
		}
	}
	return "", "", 0, nil
}

func TestTransferStat(t *testing.T) {
	in := &scriptInner{replies: map[string]scriptReply{
		`'C:\t\f.txt'`: {stdout: `{"is_dir":false,"size":42}`},
		`'C:\missing'`: {stderr: "not found", code: 1},
	}}
	tr := &transfer{inner: in}
	got, err := tr.Stat(context.Background(), `C:\t\f.txt`)
	if err != nil || got.IsDir || got.Size != 42 {
		t.Fatalf("got %+v %v", got, err)
	}
	if !strings.Contains(in.scripts[0], `'C:\t\f.txt'`) {
		t.Fatalf("path not quoted: %s", in.scripts[0])
	}
	if _, err := tr.Stat(context.Background(), `C:\missing`); err == nil {
		t.Fatal("missing must fail")
	}
}

func TestTransferReadDirJoins(t *testing.T) {
	in := &scriptInner{replies: map[string]scriptReply{
		"Get-ChildItem": {stdout: `[{"name":"a.txt","is_container":false,"length":1}]`},
	}}
	tr := &transfer{inner: in}
	got, err := tr.ReadDir(context.Background(), `C:\t`)
	if err != nil || len(got) != 1 || got[0].Path != `C:\t\a.txt` {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestTransferAppendChunkVerbs(t *testing.T) {
	in := &scriptInner{}
	tr := &transfer{inner: in}
	data := []byte("hello")
	if err := tr.AppendChunk(context.Background(), `C:\t\f.txt`, data, true); err != nil {
		t.Fatal(err)
	}
	if err := tr.AppendChunk(context.Background(), `C:\t\f.txt`, data, false); err != nil {
		t.Fatal(err)
	}
	if len(in.scripts) != 2 {
		t.Fatalf("expected 2 execs, got %d", len(in.scripts))
	}
	if !strings.Contains(in.scripts[0], "Set-Content") {
		t.Fatalf("first must truncate: %s", in.scripts[0])
	}
	if !strings.Contains(in.scripts[1], "Add-Content") {
		t.Fatalf("rest must append: %s", in.scripts[1])
	}
	// Payload rides base64: raw bytes must not appear literally.
	b64 := base64.StdEncoding.EncodeToString(data)
	if !strings.Contains(in.scripts[0], b64) || strings.Contains(in.scripts[0], "hello'") {
		t.Fatalf("payload not safely encoded: %s", in.scripts[0])
	}
}

func TestTransferReadAtDecodes(t *testing.T) {
	want := []byte("chunk-data")
	in := &scriptInner{replies: map[string]scriptReply{
		"OpenRead": {stdout: base64.StdEncoding.EncodeToString(want) + "\r\n"},
	}}
	tr := &transfer{inner: in}
	got, err := tr.ReadAt(context.Background(), `C:\f`, 0, 100)
	if err != nil || string(got) != string(want) {
		t.Fatalf("got %q %v", got, err)
	}
	if !strings.Contains(in.scripts[0], "Seek(0,") {
		t.Fatalf("offset missing: %s", in.scripts[0])
	}
}

func TestTransferFinalize(t *testing.T) {
	in := &scriptInner{}
	tr := &transfer{inner: in}
	if err := tr.Finalize(context.Background(), `C:\t\f.txt`); err != nil {
		t.Fatal(err)
	}
	if len(in.scripts) != 1 {
		t.Fatalf("expected 1 exec, got %d", len(in.scripts))
	}
	for _, want := range []string{"FromBase64String", "Remove-Item", `C:\t\f.txt.agent-remote-b64`, "New-Item"} {
		if !strings.Contains(in.scripts[0], want) {
			t.Fatalf("finalize missing %q: %s", want, in.scripts[0])
		}
	}
}

func TestTransferParent(t *testing.T) {
	tr := &transfer{}
	if tr.Parent(`C:\a\b`) != `C:\a` {
		t.Fatal("parent wrong")
	}
}

var _ usecase.TransferClient = (*transfer)(nil)
