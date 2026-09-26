package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-remote/internal/domain"
)

func writeTempScript(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.sh")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDetectInterpreter(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"#!/bin/bash\necho hi", "bash"},
		{"#!/bin/sh\necho hi", "sh"},
		{"#!/usr/bin/env python3\nprint('hi')", "python3"},
		{"#!/usr/bin/env python\nprint('hi')", "python"},
		{"#!/usr/bin/env node\nconsole.log('hi')", "node"},
		{"#!/usr/bin/env ruby\nputs 'hi'", "ruby"},
		{"#!/bin/zsh\necho hi", "zsh"},
		{"echo no shebang", "bash"},
		{"", "bash"},
	}
	for _, tc := range cases {
		got := detectInterpreter([]byte(tc.content))
		if got != tc.want {
			t.Errorf("detectInterpreter(%q) = %q, want %q", tc.content, got, tc.want)
		}
	}
}

func TestBuildScriptCommand(t *testing.T) {
	content := []byte("echo hello")
	cmd := buildScriptCommand(content, "bash", []string{"--verbose", "arg2"})
	if !strings.Contains(cmd, "base64 -d | bash --verbose arg2") {
		t.Fatalf("unexpected command: %s", cmd)
	}
	if !strings.Contains(cmd, "ZWNobyBoZWxsbw==") { // base64("echo hello")
		t.Fatal("script content not base64-encoded in command")
	}
}

func TestRunScriptSingleHost(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	if out, _ := Run([]string{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "env", "--auth-ref", "PW"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("add: %v", out.ToolErr)
	}
	path := writeTempScript(t, "#!/bin/bash\necho script-ok\n")
	out, _ := Run([]string{"script", "h", "--", path}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("script: %v", out.ToolErr)
	}
	if !out.RemoteRan || out.ExitCode() != ExitOK {
		t.Fatalf("unexpected outcome: %+v", out)
	}
}

func TestRunScriptMissingFile(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	out, _ := Run([]string{"script", "h", "--", "/nonexistent/script.sh"}, opt, deps)
	if domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %+v", out)
	}
}

func TestRunScriptTooLarge(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	big := strings.Repeat("x", maxInlineScript+1)
	path := writeTempScript(t, big)
	out, _ := Run([]string{"script", "h", "--", path}, opt, deps)
	if out.ToolErr == nil || !strings.Contains(out.ToolErr.Error(), "max inline") {
		t.Fatalf("expected size error, got %+v", out)
	}
}

func TestRunScriptInputErrors(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	for _, args := range [][]string{
		{"script", "h", "echo"},
		{"script", "--", "echo"},
		{"script"},
	} {
		if out, _ := Run(args, opt, deps); out.ToolErr == nil {
			t.Fatalf("%v: expected error", args)
		}
	}
}
