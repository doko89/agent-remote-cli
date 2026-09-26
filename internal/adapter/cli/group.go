package cli

import (
	"fmt"
	"strings"

	"agent-remote/internal/adapter/presenter"
	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

func groupUsage() string {
	return `usage: group <sub-command> [args]

  group list                        list all groups and their hosts
  group rename <old> <new>          rename a group on all member hosts
  group move <host> <group>         move one host to a group (empty = ungroup)
  group remove <group>              ungroup all hosts in a group`
}

func runGroup(args []string, d Deps) Outcome {
	if len(args) == 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, groupUsage()))
	}
	switch args[0] {
	case "list":
		return runGroupList(args[1:], d)
	case "rename":
		return runGroupRename(args[1:], d)
	case "move":
		return runGroupMove(args[1:], d)
	case "remove":
		return runGroupRemove(args[1:], d)
	default:
		return fail(domain.Fail(domain.CodeInvalidInput, groupUsage()))
	}
}

func runGroupList(args []string, d Deps) Outcome {
	if len(args) != 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: group list"))
	}
	groups, err := usecase.ListGroups(d.Store)
	if err != nil {
		return fail(err)
	}
	type groupView struct {
		Name  string   `json:"name"`
		Hosts []string `json:"hosts"`
	}
	views := make([]groupView, 0, len(groups))
	var rawLines []string
	for _, g := range groups {
		views = append(views, groupView{Name: g.Name, Hosts: g.Hosts})
		rawLines = append(rawLines, g.Name+"\t"+strings.Join(g.Hosts, ", "))
	}
	if len(rawLines) == 0 {
		rawLines = []string{"no groups configured"}
	}
	return Outcome{
		Data:   map[string]any{"groups": views},
		RawOut: strings.Join(rawLines, "\n"),
	}
}

func runGroupRename(args []string, d Deps) Outcome {
	if len(args) != 2 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: group rename <old> <new>"))
	}
	count, err := usecase.RenameGroup(d.Store, args[0], args[1])
	if err != nil {
		return fail(err)
	}
	raw := fmt.Sprintf("renamed group %s -> %s (%d hosts)", args[0], args[1], count)
	return Outcome{
		Data:   map[string]any{"from": args[0], "to": args[1], "hosts": count},
		RawOut: raw,
	}
}

func runGroupMove(args []string, d Deps) Outcome {
	if len(args) != 2 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: group move <host> <group>"))
	}
	h, err := usecase.MoveGroup(d.Store, args[0], args[1])
	if err != nil {
		return fail(err)
	}
	raw := fmt.Sprintf("moved host %s to group %q", h.Name, h.Group)
	return Outcome{
		Data:   map[string]any{"host": presenter.ViewHost(h)},
		RawOut: raw,
	}
}

func runGroupRemove(args []string, d Deps) Outcome {
	if len(args) != 1 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: group remove <group>"))
	}
	count, err := usecase.RemoveGroup(d.Store, args[0])
	if err != nil {
		return fail(err)
	}
	raw := fmt.Sprintf("removed group %s (%d hosts ungrouped)", args[0], count)
	return Outcome{
		Data:   map[string]any{"removed": args[0], "hosts": count},
		RawOut: raw,
	}
}
