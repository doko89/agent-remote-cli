package usecase

import (
	"sort"
	"strings"

	"agent-remote/internal/domain"
)

// GroupInfo describes one group label and its member host names.
type GroupInfo struct {
	Name  string
	Hosts []string
}

// validateGroupName rejects empty labels and commas (which would break
// the comma-separated multi-target exec syntax).
func validateGroupName(group string) error {
	group = strings.TrimSpace(group)
	if group == "" {
		return domain.Fail(domain.CodeInvalidInput, "group name must not be empty")
	}
	if strings.Contains(group, ",") {
		return domain.Fail(domain.CodeInvalidInput, "group name must not contain commas")
	}
	return nil
}

// RenameGroup rewrites the group label on every host that belongs to the
// old group. Hosts and secrets are untouched — only the label changes.
func RenameGroup(store HostStore, oldGroup, newGroup string) (int, error) {
	if err := validateGroupName(oldGroup); err != nil {
		return 0, err
	}
	if err := validateGroupName(newGroup); err != nil {
		return 0, err
	}
	hosts, err := store.Load()
	if err != nil {
		return 0, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	count := 0
	for name, h := range hosts {
		if h.Group == oldGroup {
			h.Group = newGroup
			hosts[name] = h
			count++
		}
	}
	if count == 0 {
		return 0, domain.Fail(domain.CodeInvalidInput, "no hosts in group "+oldGroup)
	}
	if err := store.Save(hosts); err != nil {
		return 0, domain.Fail(domain.CodeStoreError, saveStoreErr+err.Error())
	}
	return count, nil
}

// MoveGroup sets the group label on one host. Pass an empty newGroup to
// remove the host from its current group.
func MoveGroup(store HostStore, hostName, newGroup string) (domain.Host, error) {
	newGroup = strings.TrimSpace(newGroup)
	if err := validateGroupName(newGroup); newGroup != "" && err != nil {
		return domain.Host{}, err
	}
	hosts, err := store.Load()
	if err != nil {
		return domain.Host{}, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	h, ok := hosts[hostName]
	if !ok {
		return domain.Host{}, hostNotFound(hostName)
	}
	h.Group = newGroup
	hosts[hostName] = h
	if err := store.Save(hosts); err != nil {
		return domain.Host{}, domain.Fail(domain.CodeStoreError, saveStoreErr+err.Error())
	}
	return h, nil
}

// RemoveGroup clears the group label from every host that carries it.
// The hosts themselves are kept.
func RemoveGroup(store HostStore, group string) (int, error) {
	if err := validateGroupName(group); err != nil {
		return 0, err
	}
	hosts, err := store.Load()
	if err != nil {
		return 0, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	count := 0
	for name, h := range hosts {
		if h.Group == group {
			h.Group = ""
			hosts[name] = h
			count++
		}
	}
	if count == 0 {
		return 0, domain.Fail(domain.CodeInvalidInput, "no hosts in group "+group)
	}
	if err := store.Save(hosts); err != nil {
		return 0, domain.Fail(domain.CodeStoreError, saveStoreErr+err.Error())
	}
	return count, nil
}

// ListGroups returns all groups sorted by name, each with a sorted member
// list. Ungrouped hosts are excluded.
func ListGroups(store HostStore) ([]GroupInfo, error) {
	hosts, err := store.Load()
	if err != nil {
		return nil, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	byGroup := map[string][]string{}
	for _, h := range hosts {
		if h.Group != "" {
			byGroup[h.Group] = append(byGroup[h.Group], h.Name)
		}
	}
	names := make([]string, 0, len(byGroup))
	for g := range byGroup {
		names = append(names, g)
	}
	sort.Strings(names)
	out := make([]GroupInfo, 0, len(names))
	for _, g := range names {
		members := byGroup[g]
		sort.Strings(members)
		out = append(out, GroupInfo{Name: g, Hosts: members})
	}
	return out, nil
}
