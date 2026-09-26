package usecase

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"agent-remote/internal/domain"
)

// ResolveTargets maps one exec targeting mode to concrete hosts: explicit
// comma-separated names, a group label, or every stored host. It preserves
// name-list order and sorts group/all results by name for determinism.
func ResolveTargets(store HostStore, names []string, group string, all bool) ([]domain.Host, error) {
	hosts, err := store.Load()
	if err != nil {
		return nil, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	switch {
	case all:
		out := make([]domain.Host, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, h)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		if len(out) == 0 {
			return nil, domain.Fail(domain.CodeInvalidInput, "no hosts configured")
		}
		return out, nil
	case group != "":
		var out []domain.Host
		for _, h := range hosts {
			if h.Group == group {
				out = append(out, h)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		if len(out) == 0 {
			return nil, domain.Fail(domain.CodeInvalidInput, "no hosts in group "+group)
		}
		return out, nil
	default:
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
func ExecFanout(ctx context.Context, store HostStore, secrets SecretResolver, factory NewClienter, targets []domain.Host, opt ExecOptions, parallel int, failFast bool) []FanoutResult {
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
			_, res, err := Exec(ctx, store, secrets, factory, h.Name, opt)
			results[i] = FanoutResult{Host: h.Name, Res: res, Err: err}
			if err != nil && failFast {
				cancel()
			}
		}(i, h)
	}
	wg.Wait()
	return results
}
