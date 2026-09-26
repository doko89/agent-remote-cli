package usecase

import (
	"testing"

	"agent-remote/internal/domain"
)

func groupTestStore(t *testing.T) *memStore {
	t.Helper()
	store := &memStore{hosts: map[string]domain.Host{}}
	inputs := []AddHostInput{
		setGroup(sshInput("web1"), "web"),
		setGroup(sshInput("web2"), "web"),
		setGroup(sshInput("db1"), "db"),
		sshInput("solo"),
	}
	for _, in := range inputs {
		if _, err := AddHost(store, in); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func setGroup(in AddHostInput, group string) AddHostInput {
	in.Group = group
	return in
}

func TestRenameGroup(t *testing.T) {
	store := groupTestStore(t)
	count, err := RenameGroup(store, "web", "staging")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("renamed %d hosts, want 2", count)
	}
	if store.hosts["web1"].Group != "staging" || store.hosts["web2"].Group != "staging" {
		t.Fatal("group label not rewritten")
	}
	if store.hosts["db1"].Group != "db" || store.hosts["solo"].Group != "" {
		t.Fatal("unrelated hosts changed")
	}
	if _, err := RenameGroup(store, "missing", "x"); err == nil {
		t.Fatal("expected error for missing group")
	}
}

func TestMoveGroup(t *testing.T) {
	store := groupTestStore(t)
	h, err := MoveGroup(store, "solo", "staging")
	if err != nil {
		t.Fatal(err)
	}
	if h.Group != "staging" || store.hosts["solo"].Group != "staging" {
		t.Fatalf("unexpected group: %+v", h)
	}
	h, err = MoveGroup(store, "solo", "")
	if err != nil {
		t.Fatal(err)
	}
	if h.Group != "" {
		t.Fatalf("expected empty group, got %q", h.Group)
	}
	if _, err := MoveGroup(store, "ghost", "web"); domain.CodeOf(err) != domain.CodeHostNotFound {
		t.Fatalf("expected host_not_found, got %v", err)
	}
}

func TestRemoveGroup(t *testing.T) {
	store := groupTestStore(t)
	count, err := RemoveGroup(store, "web")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("removed %d hosts, want 2", count)
	}
	if store.hosts["web1"].Group != "" || store.hosts["web2"].Group != "" {
		t.Fatal("group not cleared")
	}
	if _, err := RemoveGroup(store, "web"); err == nil {
		t.Fatal("expected error for already-empty group")
	}
}

func TestListGroups(t *testing.T) {
	store := groupTestStore(t)
	groups, err := ListGroups(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("group count: %d, want 2", len(groups))
	}
	if groups[0].Name != "db" || groups[1].Name != "web" {
		t.Fatalf("unexpected order: %+v", groups)
	}
	if groups[1].Hosts[0] != "web1" || groups[1].Hosts[1] != "web2" {
		t.Fatalf("members not sorted: %+v", groups[1].Hosts)
	}
}

func TestGroupNameValidation(t *testing.T) {
	store := groupTestStore(t)
	for _, tc := range []struct {
		old, new string
	}{{"", "x"}, {"web", ""}, {"web", "a,b"}} {
		if _, err := RenameGroup(store, tc.old, tc.new); err == nil {
			t.Fatalf("RenameGroup(%q,%q): expected error", tc.old, tc.new)
		}
	}
	if _, err := MoveGroup(store, "solo", "a,b"); err == nil {
		t.Fatal("MoveGroup comma: expected error")
	}
	if _, err := RemoveGroup(store, "a,b"); err == nil {
		t.Fatal("RemoveGroup comma: expected error")
	}
}
