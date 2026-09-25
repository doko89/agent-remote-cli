package winrmclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

// WinRM has no file-transfer channel, so files move as base64 text through
// PowerShell in chunks. Chunk sizes stay far below the WinRM envelope limit
// (~150 KB) and keep every interpolated value base64 or single-quoted, so
// file bytes can never break out of the command string.
const (
	winReadBlock  = 192 * 1024 // raw bytes per download exec
	winWriteChars = 60000      // base64 chars per upload exec
)

// WinRMFactory builds file-transfer clients. It reuses the raw-NTLM sealed
// transport: transfers demand encryption exactly like commands do.
type WinRMFactory struct {
	// DialTimeout bounds the underlying TCP connection.
	DialTimeout time.Duration
}

// NewTransferClient builds the endpoint client. Like commands, it connects
// lazily on first use; network errors surface classified from each method.
func (f WinRMFactory) NewTransferClient(h domain.Host, password string) (usecase.TransferClient, error) {
	base, err := Factory{DialTimeout: f.DialTimeout}.NewClient(h, password)
	if err != nil {
		return nil, err
	}
	inner, ok := base.(*client)
	if !ok {
		return nil, domain.Fail(domain.CodeInternal, "unexpected winrm client type")
	}
	return &transfer{inner: inner.inner}, nil
}

type transfer struct {
	// inner is *winrm.Client, kept behind an interface for tests.
	inner interface {
		RunPSWithContext(ctx context.Context, command string) (string, string, int, error)
	}
}

// psQuote renders a PowerShell single-quoted string literal. Embedded quotes
// double up per PowerShell rules; nothing else interpolates.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// winParent returns the containing directory of a Windows path, tolerating
// both separators since Copy joins children with "/".
func winParent(p string) string {
	p = strings.TrimRight(p, `/\`)
	best := -1
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			best = i
			break
		}
	}
	if best <= 0 {
		return p
	}
	return p[:best]
}

// splitB64 cuts s into pieces of at most n chars for Add-Content execs.
func splitB64(s string, n int) []string {
	var out []string
	for len(s) > 0 {
		m := n
		if m > len(s) {
			m = len(s)
		}
		out = append(out, s[:m])
		s = s[m:]
	}
	return out
}

func (t *transfer) Stat(ctx context.Context, p string) (usecase.RemoteFile, error) {
	// The JSON is concatenation, never interpolation: PowerShell would
	// otherwise parse the braces as a script block.
	out, err := t.ps(ctx, fmt.Sprintf(
		`if (Test-Path -LiteralPath %s -PathType Container) { '{"is_dir":true}' } `+
			`elseif (Test-Path -LiteralPath %s -PathType Leaf) { `+
			`$l=(Get-Item -LiteralPath %s).Length; '{"is_dir":false,"size":' + $l + '}' } `+
			`else { exit 1 }`, psQuote(p), psQuote(p), psQuote(p)))
	if err != nil {
		return usecase.RemoteFile{}, err
	}
	var v struct {
		IsDir bool  `json:"is_dir"`
		Size  int64 `json:"size"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return usecase.RemoteFile{}, domain.Fail(domain.CodeInternal, "cannot parse stat output: "+err.Error())
	}
	return usecase.RemoteFile{Path: p, IsDir: v.IsDir, Size: v.Size}, nil
}

type winDirEntry struct {
	Name        string `json:"name"`
	IsContainer bool   `json:"is_container"`
	Length      *int64 `json:"length"`
}

func (t *transfer) ReadDir(ctx context.Context, p string) ([]usecase.RemoteFile, error) {
	out, err := t.ps(ctx, fmt.Sprintf(
		`Get-ChildItem -LiteralPath %s -Force | `+
			`Select-Object @{n='name';e={$_.Name}},@{n='is_container';e={$_.PSIsContainer}},@{n='length';e={$_.Length}} | `+
			`ConvertTo-Json -Compress`, psQuote(p)))
	if err != nil {
		return nil, err
	}
	entries, err := parseDirJSON(out)
	if err != nil {
		return nil, err
	}
	joined := winJoin(p)
	out2 := make([]usecase.RemoteFile, 0, len(entries))
	for _, e := range entries {
		var size int64
		if e.Length != nil {
			size = *e.Length
		}
		out2 = append(out2, usecase.RemoteFile{Path: joined + e.Name, IsDir: e.IsContainer, Size: size})
	}
	return out2, nil
}

// parseDirJSON decodes ConvertTo-Json output, which is an object for one
// entry, an array for many, and empty for none.
func parseDirJSON(out string) ([]winDirEntry, error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []winDirEntry
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, domain.Fail(domain.CodeInternal, "cannot parse dir listing: "+err.Error())
		}
		return arr, nil
	}
	var one winDirEntry
	if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
		return nil, domain.Fail(domain.CodeInternal, "cannot parse dir listing: "+err.Error())
	}
	return []winDirEntry{one}, nil
}

// winJoin returns p with exactly one trailing backslash for name appends.
func winJoin(p string) string {
	return strings.TrimRight(p, `/\`) + `\`
}

func (t *transfer) MkdirAll(ctx context.Context, p string) error {
	_, err := t.ps(ctx, fmt.Sprintf(
		`New-Item -ItemType Directory -Force -Path %s | Out-Null`, psQuote(p)))
	return err
}

func (t *transfer) ReadAt(ctx context.Context, p string, offset int64, n int) ([]byte, error) {
	out, err := t.ps(ctx, fmt.Sprintf(
		`$s=[IO.File]::OpenRead(%s); try { $s.Seek(%d,[IO.SeekOrigin]::Begin)|Out-Null; `+
			`$b=New-Object byte[] %d; $r=$s.Read($b,0,%d); `+
			`if ($r -gt 0) { [Convert]::ToBase64String($b,0,$r) } } finally { $s.Close() }`,
		psQuote(p), offset, n, n))
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil // EOF
	}
	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		return nil, domain.Fail(domain.CodeInternal, "cannot decode download chunk: "+err.Error())
	}
	return raw, nil
}

// stageSuffix marks the sidecar holding base64 chunks until Finalize.
const stageSuffix = ".agent-remote-b64"

func stagePath(p string) string { return p + stageSuffix }

func (t *transfer) AppendChunk(ctx context.Context, p string, data []byte, first bool) error {
	stage := stagePath(p)
	b64 := base64.StdEncoding.EncodeToString(data)
	verb := "Add-Content"
	if first {
		verb = "Set-Content"
	}
	for _, piece := range splitB64(b64, winWriteChars) {
		if _, err := t.ps(ctx, fmt.Sprintf(
			`%s -LiteralPath %s -Value %s -NoNewline`, verb, psQuote(stage), psQuote(piece))); err != nil {
			return err
		}
		verb = "Add-Content" // only the first piece truncates
	}
	return nil
}

// Finalize decodes the staged base64 into the destination bytes and removes
// the sidecar. A missing sidecar means zero chunks flowed: the destination
// is created empty instead.
func (t *transfer) Finalize(ctx context.Context, p string) error {
	stage := stagePath(p)
	_, err := t.ps(ctx, fmt.Sprintf(
		`if (Test-Path -LiteralPath %s -PathType Leaf) { `+
			`[IO.File]::WriteAllBytes(%s, [Convert]::FromBase64String([IO.File]::ReadAllText(%s))); `+
			`Remove-Item -LiteralPath %s -Force } `+
			`else { New-Item -Path %s -ItemType File -Force | Out-Null }`,
		psQuote(stage), psQuote(p), psQuote(stage), psQuote(stage), psQuote(p)))
	return err
}

func (t *transfer) Parent(p string) string { return winParent(p) }

func (t *transfer) Close() error { return nil }

// ps runs one PowerShell fragment and returns trimmed stdout. A non-zero
// exit maps to invalid_input when the fragment signals missing paths, and
// to a classified transport error otherwise.
func (t *transfer) ps(ctx context.Context, fragment string) (string, error) {
	stdout, stderr, code, err := t.inner.RunPSWithContext(ctx, fragment)
	if err != nil {
		if ctx.Err() != nil {
			return "", domain.Fail(domain.CodeTimeout, "winrm transfer timed out")
		}
		return "", classify(err)
	}
	if code != 0 {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = "remote path not found"
		}
		return "", domain.Fail(domain.CodeInvalidInput, msg)
	}
	return strings.TrimSpace(stdout), nil
}
