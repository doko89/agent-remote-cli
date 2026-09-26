package usecase

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-remote/internal/domain"
)

type fanoutClient struct {
	result domain.ExecResult
	err    error
}

func (c *fanoutClient) Test(context.Context) (domain.TestResult, error) {
	return domain.TestResult{Reachable: true}, nil
}

func (c *fanoutClient) Exec(context.Context, string) (domain.ExecResult, error) {
	time.Sleep(10 * time.Millisecond)
	return c.result, c.err
}

func (c *fanoutClient) Close() error { return nil }

type fanoutFactory struct {
	clients map[string]*fanoutClient
	mu      sync.Mutex
	calls   map[string]int
}

func newFanoutFactory() *fanoutFactory {
	return &fanoutFactory{clients: map[string]*fanoutClient{}, calls: map[string]int{}}
}

func (f *fanoutFactory) client(h domain.Host) *fanoutClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.clients[h.Name]
	if c == nil {
		c = &fanoutClient{}
		f.clients[h.Name] = c
	}
	return c
}

func (f *fanoutFactory) NewClient(h domain.Host, _ string) (RemoteClient, error) {
	c := f.client(h)
	f.mu.Lock()
	f.calls[h.Name]++
	f.mu.Unlock()
	return c, nil
}

func (f *fanoutFactory) callCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func fanoutHosts(t *testing.T) (*memStore, []domain.Host) {
	t.Helper()
	store := &memStore{hosts: map[string]domain.Host{}}
	var hosts []domain.Host
	for _, name := range []string{"web2", "web1", "db1"} {
		in := sshInput(name)
		if name != "db1" {
			in.Group = "web"
		}
		h, err := AddHost(store, in)
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}
	return store, hosts
}

func TestResolveTargets(t *testing.T) {
	store, _ := fanoutHosts(t)
	cases := []struct {
		name  string
		names []string
		group string
		all   bool
		want  []string
	}{
		{"names preserve order", []string{"web2", "web1"}, "", false, []string{"web2", "web1"}},
		{"group sorts by name", nil, "web", false, []string{"web1", "web2"}},
		{"all sorts by name", nil, "", true, []string{"db1", "web1", "web2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hosts, err := ResolveTargets(store, tc.names, tc.group, tc.all)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(hosts))
			for _, h := range hosts {
				got = append(got, h.Name)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}

	if _, err := ResolveTargets(store, []string{"web1", "ghost"}, "", false); domain.CodeOf(err) != domain.CodeHostNotFound {
		t.Fatalf("expected host_not_found, got %v", err)
	}
	if _, err := ResolveTargets(store, nil, "missing", false); domain.CodeOf(err) != domain.CodeInvalidInput {
		t.Fatalf("expected invalid_input, got %v", err)
	}
}

func TestExecFanoutAggregatesAndLimits(t *testing.T) {
	store, hosts := fanoutHosts(t)
	factory := newFanoutFactory()
	factory.client(hosts[0]).err = errors.New("connect failed")
	factory.client(hosts[1]).result = domain.ExecResult{ExitCode: 1}
	factory.client(hosts[2]).result = domain.ExecResult{Stdout: "ok"}

	results := ExecFanout(context.Background(), store, stubSecrets{}, factory, hosts,
		ExecOptions{Command: "uptime", Timeout: time.Second}, 2, false)
	if len(results) != 3 {
		t.Fatalf("result count: %d", len(results))
	}
	if results[0].Err == nil || results[1].Res.ExitCode != 1 || results[2].Res.Stdout != "ok" {
		t.Fatalf("unexpected results: %+v", results)
	}
	for _, h := range hosts {
		if factory.callCount(h.Name) != 1 {
			t.Fatalf("%s executed %d times", h.Name, factory.callCount(h.Name))
		}
	}
}

func TestExecFanoutFailFastSkipsPending(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	var hosts []domain.Host
	for _, name := range []string{"slow", "late1", "late2", "late3", "late4"} {
		h, err := AddHost(store, sshInput(name))
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}
	factory := newFanoutFactory()
	factory.client(hosts[0]).err = errors.New("boom")

	results := ExecFanout(context.Background(), store, stubSecrets{}, factory, hosts,
		ExecOptions{Command: "uptime", Timeout: time.Second}, 1, true)
	if results[0].Err == nil {
		t.Fatal("expected first host error")
	}
	skipped := 0
	for _, r := range results[1:] {
		if r.Err != nil && r.Res == (domain.ExecResult{}) {
			skipped++
		} else if factory.callCount(r.Host) != 1 {
			t.Fatalf("%s unexpectedly not executed", r.Host)
		}
	}
	if skipped == 0 {
		t.Fatal("expected pending hosts to be skipped")
	}
}
