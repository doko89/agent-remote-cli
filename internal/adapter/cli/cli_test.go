package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

type memStore struct{ hosts map[string]domain.Host }

func (m *memStore) Load() (map[string]domain.Host, error) {
	out := map[string]domain.Host{}
	for k, v := range m.hosts {
		out[k] = v
	}
	return out, nil
}

func (m *memStore) Save(h map[string]domain.Host) error { m.hosts = h; return nil }

type stubSecrets struct{}

func (stubSecrets) Resolve(h domain.Host) (string, error) { return "pw", nil }
func (stubSecrets) Delete(string) error                   { return nil }

type stubClient struct{}

func (stubClient) Test(context.Context) (domain.TestResult, error) {
	return domain.TestResult{Reachable: true}, nil
}
func (stubClient) Exec(context.Context, string) (domain.ExecResult, error) {
	return domain.ExecResult{Stdout: "hi\n", ExitCode: 0}, nil
}
func (stubClient) Close() error { return nil }

type stubFactory struct{}

func (stubFactory) NewClient(domain.Host, string) (usecase.RemoteClient, error) {
	return stubClient{}, nil
}

func testDeps() Deps {
	return Deps{Store: &memStore{hosts: map[string]domain.Host{}}, Secrets: stubSecrets{}, Factory: stubFactory{}}
}

func run(t *testing.T, args []string, stdin string) (Outcome, Options) {
	t.Helper()
	opt := Options{Stdin: strings.NewReader(stdin), Version: "test"}
	return Run(args, opt, testDeps())
}

func TestExecRequiresSeparator(t *testing.T) {
	out, _ := run(t, []string{"exec", "h", "echo", "hi"}, "")
	if out.ToolErr == nil || domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %+v", out)
	}
	if out.ExitCode() != ExitToolFail {
		t.Fatalf("expected exit 2, got %d", out.ExitCode())
	}
}

func TestExecUnknownHostExit2(t *testing.T) {
	out, _ := run(t, []string{"exec", "nope", "--", "echo", "hi"}, "")
	if domain.CodeOf(out.ToolErr) != domain.CodeHostNotFound || out.ExitCode() != 2 {
		t.Fatalf("got %+v", out)
	}
}

func TestAddKeyringRequiresSecretSource(t *testing.T) {
	out, _ := run(t, []string{"add", "ssh", "h", "--host", "a", "--user", "u"}, "")
	if domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("keyring add without secret must fail, got %+v", out)
	}
}

func TestAddWinrmRejectsKeyfile(t *testing.T) {
	out, _ := run(t, []string{"add", "winrm", "h", "--host", "a", "--user", "u",
		"--auth", "keyfile", "--auth-ref", "/tmp/k"}, "")
	if domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %+v", out)
	}
}

func TestAddShowExecRoundTrip(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	out, _ := Run([]string{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "env", "--auth-ref", "PW"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("add: %v", out.ToolErr)
	}
	out, _ = Run([]string{"exec", "h", "--", "echo", "hi"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("exec: %v", out.ToolErr)
	}
	if out.ExitCode() != ExitOK || !out.RemoteRan {
		t.Fatalf("expected clean remote run, got %+v", out)
	}
}

func TestManageFlows(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	add := []string{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "env", "--auth-ref", "PW"}
	if out, _ := Run(add, opt, deps); out.ToolErr != nil {
		t.Fatalf("add: %v", out.ToolErr)
	}
	if out, _ := Run(add, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeHostExists {
		t.Fatalf("duplicate: %+v", out)
	}
	if out, _ := Run([]string{"list"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("list: %v", out.ToolErr)
	}
	if out, _ := Run([]string{"show", "h"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("show: %v", out.ToolErr)
	}
	if out, _ := Run([]string{"show", "nope"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeHostNotFound {
		t.Fatalf("show missing: %+v", out)
	}
	if out, _ := Run([]string{"test", "h", "--timeout", "5s"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("test: %v", out.ToolErr)
	}
	if out, _ := Run([]string{"test", "h", "--timeout", "0s"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("bad timeout: %+v", out)
	}
	if out, _ := Run([]string{"exec", "h", "--no-filter", "--", "echo", "-n", "hi"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("exec: %v", out.ToolErr)
	}
	if out, _ := Run([]string{"rm", "h"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("rm: %v", out.ToolErr)
	}
	if out, _ := Run([]string{"rm", "h"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeHostNotFound {
		t.Fatalf("rm twice: %+v", out)
	}
}

func TestRenameFlow(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	add := []string{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "env", "--auth-ref", "PW"}
	if out, _ := Run(add, opt, deps); out.ToolErr != nil {
		t.Fatalf("add: %v", out.ToolErr)
	}
	if out, _ := Run([]string{"rename", "h", "h2"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("rename: %v", out.ToolErr)
	}
	if hosts, _ := deps.Store.Load(); len(hosts) != 1 || hosts["h2"].Name != "h2" {
		t.Fatalf("store after rename: %+v", hosts)
	}
	if out, _ := Run([]string{"show", "h"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeHostNotFound {
		t.Fatalf("old name must be gone: %+v", out)
	}
	if out, _ := Run([]string{"rename", "ghost", "x"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeHostNotFound {
		t.Fatalf("missing old: %+v", out)
	}
	if out, _ := Run([]string{"rename", "h2", "h2"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("same name: %+v", out)
	}
}

func TestUnknownAndHelp(t *testing.T) {
	opt := Options{Version: "v1"}
	deps := testDeps()
	if out, _ := Run([]string{"bogus"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("unknown: %+v", out)
	}
	if out, _ := Run([]string{"version"}, opt, deps); out.RawOut != "v1" {
		t.Fatalf("version: %+v", out)
	}
	if out, _ := Run([]string{"help"}, opt, deps); out.ToolErr != nil || out.RawOut == "" {
		t.Fatalf("help: %+v", out)
	}
	if out, _ := Run([]string{"add", "ssh", "--help"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("add help: %+v", out)
	}
	if out, _ := Run([]string{"add", "telnet", "h"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeInvalidInput {
		t.Fatalf("bad proto: %+v", out)
	}
}

func TestGlobalsParsed(t *testing.T) {
	deps := testDeps()
	_, opt := Run([]string{"--raw", "--pretty", "--config", "/tmp/x.json", "list"}, Options{Version: "t"}, deps)
	if !opt.Raw || !opt.Pretty || opt.ConfigPath != "/tmp/x.json" {
		t.Fatalf("globals not parsed: %+v", opt)
	}
}

func TestAddRejectsBadInput(t *testing.T) {
	opt := Options{Version: "test"}
	deps := testDeps()
	cases := [][]string{
		{"add", "ssh"},
		{"add", "ssh", "h"},
		{"add", "ssh", "h", "--host", "a"}, // missing user
		{"add", "ssh", "h", "--host", "a", "--user", "u", "--filter-pattern", "(["},
		{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "keyfile"}, // missing key path
		{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "env", "--password-stdin"},
		{"add", "winrm", "h", "--host", "a", "--user", "u", "--transport", "ftp", "--auth", "stdin"},
		{"add", "winrm", "h", "--host", "a", "--user", "u", "--auth", "keyring", "--password-stdin", "--password-env", "V"},
	}
	for i, args := range cases {
		if out, _ := Run(args, opt, deps); out.ToolErr == nil {
			t.Fatalf("case %d (%v): expected error", i, args)
		}
	}
}

func TestExecTestArgcErrors(t *testing.T) {
	opt := Options{Version: "test"}
	deps := testDeps()
	for _, args := range [][]string{
		{"rm", "a", "b"},
		{"rm"},
		{"rm", "--force", "a"},
		{"list", "extra"},
		{"show"},
		{"show", "a", "b"},
		{"test"},
		{"test", "--flag", "a"},
		{"exec"},
		{"exec", "--", "echo"},
		{"exec", "h", "--"},
		{"exec", "h", "--timeout", "bogus", "--", "echo"},
		{"exec", "h", "--timeout", "0s", "--", "echo"},
	} {
		if out, _ := Run(args, opt, deps); out.ToolErr == nil {
			t.Fatalf("%v: expected error", args)
		}
	}
}

func TestOneShotOverrides(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	if out, _ := Run([]string{"add", "ssh", "h", "--host", "a", "--user", "u", "--auth", "stdin"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("add: %v", out.ToolErr)
	}
	t.Setenv("AR_CLI_TEST_PW", "envpw")
	if out, _ := Run([]string{"exec", "h", "--password-env", "AR_CLI_TEST_PW", "--", "echo", "hi"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("exec env override: %v", out.ToolErr)
	}
	opt.Stdin = strings.NewReader("piped\n")
	if out, _ := Run([]string{"test", "h", "--password-stdin"}, opt, deps); out.ToolErr != nil {
		t.Fatalf("test stdin override: %v", out.ToolErr)
	}
	if out, _ := Run([]string{"exec", "h", "--password-env", "AR_CLI_MISSING_XYZ", "--", "echo"}, opt, deps); domain.CodeOf(out.ToolErr) != domain.CodeSecretUnavailable {
		t.Fatalf("missing env: %+v", out)
	}
}

func TestReadPipePassword(t *testing.T) {
	got, err := readPipePassword(strings.NewReader("pw\n"))
	if err != nil || got != "pw" {
		t.Fatalf("got %q, %v", got, err)
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer devnull.Close()
	if _, err := readPipePassword(devnull); domain.CodeOf(err) != domain.CodeSecretUnavailable {
		t.Fatalf("expected TTY refusal, got %v", err)
	}
}

func TestExitCodeMapping(t *testing.T) {
	if (Outcome{RemoteRan: true, RemoteExit: 3}).ExitCode() != ExitRemoteKo {
		t.Fatal("remote non-zero must map to exit 1")
	}
	if (Outcome{ToolErr: domain.Fail(domain.CodeTimeout, "t")}).ExitCode() != ExitToolFail {
		t.Fatal("tool error must map to exit 2")
	}
	if (Outcome{}).ExitCode() != ExitOK {
		t.Fatal("empty outcome must map to exit 0")
	}
}
