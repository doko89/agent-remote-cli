package cli

import (
	"encoding/json"
	"testing"

	"agent-remote/internal/domain"
)

func testHosts(deps Deps) map[string]domain.Host {
	return deps.Store.(*memStore).hosts
}

func TestGroupCommands(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	adds := [][]string{
		{"add", "ssh", "web1", "--host", "a", "--user", "u", "--group", "web", "--auth", "env", "--auth-ref", "PW"},
		{"add", "ssh", "web2", "--host", "a", "--user", "u", "--group", "web", "--auth", "env", "--auth-ref", "PW"},
	}
	for _, args := range adds {
		if out, _ := Run(args, opt, deps); out.ToolErr != nil {
			t.Fatalf("add: %v", out.ToolErr)
		}
	}

	out, _ := Run([]string{"group", "list"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("group list: %v", out.ToolErr)
	}
	var listBody struct {
		Groups []struct {
			Name  string   `json:"name"`
			Hosts []string `json:"hosts"`
		} `json:"groups"`
	}
	raw, _ := json.Marshal(out.Data)
	if err := json.Unmarshal(raw, &listBody); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listBody.Groups) != 1 || listBody.Groups[0].Name != "web" || len(listBody.Groups[0].Hosts) != 2 {
		t.Fatalf("unexpected groups: %+v", listBody.Groups)
	}

	out, _ = Run([]string{"group", "rename", "web", "staging"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("group rename: %v", out.ToolErr)
	}
	hosts := testHosts(deps)
	if hosts["web1"].Group != "staging" || hosts["web2"].Group != "staging" {
		t.Fatal("rename not persisted")
	}

	out, _ = Run([]string{"group", "move", "web1", "prod"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("group move: %v", out.ToolErr)
	}
	hosts = testHosts(deps)
	if hosts["web1"].Group != "prod" {
		t.Fatalf("move not persisted: %q", hosts["web1"].Group)
	}

	out, _ = Run([]string{"group", "remove", "staging"}, opt, deps)
	if out.ToolErr != nil {
		t.Fatalf("group remove: %v", out.ToolErr)
	}
	hosts = testHosts(deps)
	if hosts["web2"].Group != "" {
		t.Fatalf("remove not persisted: %q", hosts["web2"].Group)
	}
}

func TestGroupInputErrors(t *testing.T) {
	deps := testDeps()
	opt := Options{Version: "test"}
	for _, args := range [][]string{
		{"group"},
		{"group", "bogus"},
		{"group", "list", "extra"},
		{"group", "rename", "a"},
		{"group", "rename", "a", "b", "c"},
		{"group", "move", "a"},
		{"group", "move", "a", "b", "c"},
		{"group", "remove"},
		{"group", "remove", "a", "b"},
		{"group", "rename", "missing", "new"},
		{"group", "remove", "missing"},
		{"group", "move", "ghost", "web"},
	} {
		if out, _ := Run(args, opt, deps); out.ToolErr == nil {
			t.Fatalf("%v: expected error", args)
		}
	}
}
