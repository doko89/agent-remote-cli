package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-remote/internal/domain"
)

// memStore is a fake HostStore.
type memStore struct {
	hosts map[string]domain.Host
	err   error
}

func (m *memStore) Load() (map[string]domain.Host, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := map[string]domain.Host{}
	for k, v := range m.hosts {
		out[k] = v
	}
	return out, nil
}

func (m *memStore) Save(hosts map[string]domain.Host) error {
	if m.err != nil {
		return m.err
	}
	m.hosts = hosts
	return nil
}

// stubSecrets is a fake SecretResolver.
type stubSecrets struct{ pw string }

func (s stubSecrets) Resolve(domain.Host) (string, error) { return s.pw, nil }
func (s stubSecrets) Delete(string) error                 { return nil }

// stubClient returns canned results and records calls.
type stubClient struct {
	execRes domain.ExecResult
	execErr error
	execs   int
	tests   int
}

func (s *stubClient) Test(context.Context) (domain.TestResult, error) {
	s.tests++
	return domain.TestResult{Reachable: true, LatencyMs: 1}, nil
}

func (s *stubClient) Exec(context.Context, string) (domain.ExecResult, error) {
	s.execs++
	return s.execRes, s.execErr
}

func (s *stubClient) Close() error { return nil }

type stubFactory struct{ client *stubClient }

func (f stubFactory) NewClient(domain.Host, string) (RemoteClient, error) {
	return f.client, nil
}

func sshInput(name string) AddHostInput {
	return AddHostInput{
		Name: name, Protocol: domain.ProtocolSSH,
		Address: "10.0.0.1", Port: 22, User: "deploy",
		Auth: domain.AuthEnv, AuthRef: "PW",
	}
}

func TestAddThenDuplicateRejected(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, err := AddHost(store, sshInput("web1")); err != nil {
		t.Fatal(err)
	}
	if _, err := AddHost(store, sshInput("web1")); err == nil {
		t.Fatal("duplicate add must fail")
	} else if domain.CodeOf(err) != domain.CodeHostExists {
		t.Fatalf("expected host_exists, got %q", domain.CodeOf(err))
	}
	// Original entry untouched.
	if store.hosts["web1"].Address != "10.0.0.1" {
		t.Fatal("duplicate add clobbered the original")
	}
}

func TestAddValidatesPerProtocol(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	winrmKey := sshInput("w")
	winrmKey.Protocol = domain.ProtocolWinRM
	winrmKey.Auth = domain.AuthKeyFile
	winrmKey.AuthRef = "/tmp/k"
	if _, err := AddHost(store, winrmKey); err == nil {
		t.Fatal("keyfile auth must be rejected for winrm")
	}
	sshWinRM := sshInput("s")
	sshWinRM.WinRMTransport = "https"
	if _, err := AddHost(store, sshWinRM); err == nil {
		t.Fatal("winrm transport must be rejected for ssh")
	}
	badPattern := sshInput("p")
	badPattern.ExtraFilterPatterns = []string{`([`}
	if _, err := AddHost(store, badPattern); err == nil {
		t.Fatal("invalid filter pattern must be rejected at add time")
	}
}

func TestExecFiltersAndKeepsRemoteFailureAsData(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	h, err := AddHost(store, sshInput("web1"))
	if err != nil {
		t.Fatal(err)
	}
	_ = h
	stub := &stubClient{execRes: domain.ExecResult{
		Stdout:   "Last login: today\nreal output\n",
		Stderr:   "boom",
		ExitCode: 3,
	}}
	_, res, err := Exec(context.Background(), store, stubSecrets{}, stubFactory{stub},
		"web1", ExecOptions{Command: "do thing", Timeout: time.Second})
	if err != nil {
		t.Fatalf("remote non-zero must not be a tool error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code lost: %d", res.ExitCode)
	}
	if res.Stdout != "real output\n" {
		t.Fatalf("banner not filtered: %q", res.Stdout)
	}
	if !res.Filtered || res.DroppedLines != 1 {
		t.Fatalf("filter stats wrong: %+v", res)
	}
	if stub.execs != 1 {
		t.Fatalf("command executed %d times, want exactly 1", stub.execs)
	}
}

func TestExecNoFilterKeepsBanner(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, err := AddHost(store, sshInput("web1")); err != nil {
		t.Fatal(err)
	}
	stub := &stubClient{execRes: domain.ExecResult{Stdout: "Welcome to X\nreal\n"}}
	_, res, err := Exec(context.Background(), store, stubSecrets{}, stubFactory{stub},
		"web1", ExecOptions{Command: "x", NoFilter: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Stdout != "Welcome to X\nreal\n" || res.Filtered || res.DroppedLines != 0 {
		t.Fatalf("--no-filter must keep everything: %+v", res)
	}
}

// TestExecNoFilterSkipsInvalidPatterns proves --no-filter bypasses pattern
// compilation so an invalid stored regex never blocks an unfiltered exec.
func TestExecNoFilterSkipsInvalidPatterns(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, err := AddHost(store, sshInput("web1")); err != nil {
		t.Fatal(err)
	}
	hosts, _ := store.Load()
	h := hosts["web1"]
	h.Filter.ExtraPatterns = []string{"(["}
	hosts["web1"] = h
	store.Save(hosts)
	stub := &stubClient{execRes: domain.ExecResult{Stdout: "raw\n"}}
	_, res, err := Exec(context.Background(), store, stubSecrets{}, stubFactory{stub},
		"web1", ExecOptions{Command: "x", NoFilter: true})
	if err != nil {
		t.Fatalf("--no-filter must skip invalid patterns: %v", err)
	}
	if res.Stdout != "raw\n" || res.Filtered {
		t.Fatalf("output must be raw: %+v", res)
	}
}

func TestExecUnknownHost(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	_, _, err := Exec(context.Background(), store, stubSecrets{}, stubFactory{&stubClient{}},
		"nope", ExecOptions{Command: "x"})
	if domain.CodeOf(err) != domain.CodeHostNotFound {
		t.Fatalf("expected host_not_found, got %v", err)
	}
}

func TestExecToolErrorPropagates(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, err := AddHost(store, sshInput("web1")); err != nil {
		t.Fatal(err)
	}
	stub := &stubClient{execErr: domain.Fail(domain.CodeConnectionFailed, "dial refused")}
	_, _, err := Exec(context.Background(), store, stubSecrets{}, stubFactory{stub},
		"web1", ExecOptions{Command: "x"})
	if domain.CodeOf(err) != domain.CodeConnectionFailed {
		t.Fatalf("expected connection_failed, got %v", err)
	}
}

func TestRemoveCleansHost(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, err := AddHost(store, sshInput("web1")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveHost(store, stubSecrets{}, "web1"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveHost(store, stubSecrets{}, "web1"); domain.CodeOf(err) != domain.CodeHostNotFound {
		t.Fatalf("expected host_not_found on second remove, got %v", err)
	}
}

func TestValidateAddTable(t *testing.T) {
	base := sshInput("x")
	cases := []struct {
		name   string
		mutate func(*AddHostInput)
	}{
		{"empty name", func(i *AddHostInput) { i.Name = " " }},
		{"bad protocol", func(i *AddHostInput) { i.Protocol = "telnet" }},
		{"empty address", func(i *AddHostInput) { i.Address = "" }},
		{"bad port", func(i *AddHostInput) { i.Port = 99999 }},
		{"empty user", func(i *AddHostInput) { i.User = "" }},
		{"bad auth", func(i *AddHostInput) { i.Auth = "flag" }},
		{"env without var", func(i *AddHostInput) { i.AuthRef = "" }},
		{"keyfile without path", func(i *AddHostInput) { i.Auth = domain.AuthKeyFile; i.AuthRef = "" }},
		{"passphrase without keyfile", func(i *AddHostInput) { i.PassphraseEnv = "V" }},
		{"winrm bad transport", func(i *AddHostInput) {
			i.Protocol = domain.ProtocolWinRM
			i.Auth = domain.AuthEnv
			i.WinRMTransport = "ssh"
		}},
	}
	for _, tc := range cases {
		in := base
		tc.mutate(&in)
		if _, err := AddHost(&memStore{hosts: map[string]domain.Host{}}, in); err == nil {
			t.Fatalf("%s: expected rejection", tc.name)
		} else if domain.CodeOf(err) != domain.CodeInvalidInput {
			t.Fatalf("%s: expected invalid_input, got %q", tc.name, domain.CodeOf(err))
		}
	}
}

func TestStoreErrorsMapped(t *testing.T) {
	broken := &memStore{err: errors.New("disk gone")}
	if _, err := AddHost(broken, sshInput("x")); domain.CodeOf(err) != domain.CodeStoreError {
		t.Fatalf("add: %v", err)
	}
	if err := RemoveHost(broken, stubSecrets{}, "x"); domain.CodeOf(err) != domain.CodeStoreError {
		t.Fatalf("remove: %v", err)
	}
	if _, err := ListHosts(broken); domain.CodeOf(err) != domain.CodeStoreError {
		t.Fatalf("list: %v", err)
	}
	if _, err := ShowHost(broken, "x"); domain.CodeOf(err) != domain.CodeStoreError {
		t.Fatalf("show: %v", err)
	}
	_, _, err := Exec(context.Background(), broken, stubSecrets{}, stubFactory{&stubClient{}}, "x", ExecOptions{Command: "y"})
	if domain.CodeOf(err) != domain.CodeStoreError {
		t.Fatalf("exec: %v", err)
	}
}

func TestTestConnection(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, err := AddHost(store, sshInput("web1")); err != nil {
		t.Fatal(err)
	}
	stub := &stubClient{}
	h, res, err := TestConnection(context.Background(), store, stubSecrets{}, stubFactory{stub}, "web1", time.Second)
	if err != nil || !res.Reachable || h.Name != "web1" || stub.tests != 1 {
		t.Fatalf("got %+v %+v %v", h, res, err)
	}
	if _, _, err := TestConnection(context.Background(), store, stubSecrets{}, stubFactory{stub}, "nope", 0); domain.CodeOf(err) != domain.CodeHostNotFound {
		t.Fatalf("expected host_not_found, got %v", err)
	}
}

func TestExecRejectsEmpty(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, _, err := Exec(context.Background(), store, stubSecrets{}, stubFactory{&stubClient{}}, "", ExecOptions{Command: "x"}); domain.CodeOf(err) != domain.CodeInvalidInput {
		t.Fatalf("empty name: %v", err)
	}
	if _, _, err := Exec(context.Background(), store, stubSecrets{}, stubFactory{&stubClient{}}, "x", ExecOptions{}); domain.CodeOf(err) != domain.CodeInvalidInput {
		t.Fatalf("empty command: %v", err)
	}
}

func TestListSorted(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	for _, n := range []string{"c", "a", "b"} {
		if _, err := AddHost(store, sshInput(n)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListHosts(store)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "a" || got[1].Name != "b" || got[2].Name != "c" {
		t.Fatalf("not sorted: %v", got)
	}
}
