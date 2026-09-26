package usecase

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"agent-remote/internal/domain"
)

// FanoutDeps bundles the shared ports passed to every worker in a fan-out.
// Grouping them keeps ExecFanout within Sonar's parameter limit and makes
// call sites self-documenting.
type FanoutDeps struct {
	Store   HostStore
	Secrets SecretResolver
	Factory NewClienter
}

// ResolveTargets maps one exec targeting mode to concrete hosts: explicit
// comma-separated names, a group label, or every stored host. It preserves
// name-list order and sorts group/all results by name for determinism.
func ResolveTargets(store HostStore, names []string, group string, all bool) ([]domain.Host, error) {
	hosts, err := store.Load()
	if err != nil {
		return nil, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	if all {
		return resolveAll(hosts)
	}
	if group != "" {
		return resolveGroup(hosts, group)
	}
	return resolveNames(hosts, names)
}

func resolveAll(hosts map[string]domain.Host) ([]domain.Host, error) {
	out := sortedHosts(hosts)
	if len(out) == 0 {
		return nil, domain.Fail(domain.CodeInvalidInput, "no hosts configured")
	}
	return out, nil
}

func resolveGroup(hosts map[string]domain.Host, group string) ([]domain.Host, error) {
	filtered := make(map[string]domain.Host)
	for name, h := range hosts {
		if h.Group == group {
			filtered[name] = h
		}
	}
	out := sortedHosts(filtered)
	if len(out) == 0 {
		return nil, domain.Fail(domain.CodeInvalidInput, "no hosts in group "+group)
	}
	return out, nil
}

func resolveNames(hosts map[string]domain.Host, names []string) ([]domain.Host, error) {
	out := make([]domain.Host, 0, len(names))
	var missing []string
	for _, n := range names {
		h, ok := hosts[n]
		if !ok {
			missing = append(missing, n)
			continue
		}
		out = append(out, h)
	}
	if len(missing) > 0 {
		return nil, hostNotFound(fmt.Sprintf("%v", missing))
	}
	return out, nil
}

func sortedHosts(hosts map[string]domain.Host) []domain.Host {
	out := make([]domain.Host, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// FanoutResult is one host's outcome in a multi-target exec: exactly one of
// Err (tool-level failure reaching/running on that host) or Res is set.
type FanoutResult struct {
	Host string
	Res  domain.ExecResult
	Err  error
}

// ExecFanout runs the same command on every target with a bounded worker
// pool, collecting one result per host. With failFast, the first failed
// host cancels scheduling of the remaining ones (in-flight hosts finish).
func ExecFanout(ctx context.Context, deps FanoutDeps, targets []domain.Host, opt ExecOptions, parallel int, failFast bool) []FanoutResult {
	if parallel <= 0 {
		parallel = defaultConcurrency
	}
	results := make([]FanoutResult, len(targets))
	index := make(map[string]int, len(targets))
	for i, h := range targets {
		index[h.Name] = i
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, h := range targets {
		if err := ctx.Err(); err != nil {
			results[i] = FanoutResult{Host: h.Name, Err: domain.Fail(domain.CodeConnectionFailed, "skipped after fail-fast")}
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			results[i] = FanoutResult{Host: h.Name, Err: domain.Fail(domain.CodeConnectionFailed, "skipped after fail-fast")}
			continue
		}
		wg.Add(1)
		go func(i int, h domain.Host) {
			defer wg.Done()
			defer func() { <-sem }()
			_, res, err := Exec(ctx, deps.Store, deps.Secrets, deps.Factory, h.Name, opt)
			results[i] = FanoutResult{Host: h.Name, Res: res, Err: err}
			if err != nil && failFast {
				cancel()
			}
		}(i, h)
	}
	wg.Wait()
	return results
}
