package usecase

import (
	"context"
	"time"

	"agent-remote/internal/domain"
)

// ExecOptions tunes one `exec` invocation. NoFilter and Format are
// independent: --raw changes the envelope rendering, never the filtering.
type ExecOptions struct {
	Command  string
	Timeout  time.Duration
	NoFilter bool
}

// Exec resolves the secret, connects, runs the command exactly once, then
// applies Lapis-2 filtering. A non-zero remote exit is NOT an error return:
// it is data inside domain.ExecResult, so callers can separate "tool broke"
// (error + exit 2) from "remote command failed" (result + exit 1).
func Exec(ctx context.Context, store HostStore, secrets SecretResolver, factory ClientFactory, name string, opt ExecOptions) (domain.Host, domain.ExecResult, error) {
	if name == "" {
		return domain.Host{}, domain.ExecResult{}, domain.Fail(domain.CodeInvalidInput, "host name must not be empty")
	}
	if opt.Command == "" {
		return domain.Host{}, domain.ExecResult{}, domain.Fail(domain.CodeInvalidInput, "remote command must not be empty")
	}
	hosts, err := store.Load()
	if err != nil {
		return domain.Host{}, domain.ExecResult{}, domain.Fail(domain.CodeStoreError, "cannot load host store: "+err.Error())
	}
	h, exists := hosts[name]
	if !exists {
		return domain.Host{}, domain.ExecResult{}, domain.Fail(domain.CodeHostNotFound, "host "+name+" not found")
	}
	password, err := secrets.Resolve(h)
	if err != nil {
		return h, domain.ExecResult{}, err
	}
	client, err := factory.NewClient(h, password)
	if err != nil {
		return h, domain.ExecResult{}, err
	}
	defer client.Close()

	timeout := timeoutOrDefault(opt.Timeout)
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	res, err := client.Exec(callCtx, opt.Command)
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		return h, res, err
	}
	cfg := h.Filter
	if opt.NoFilter {
		cfg.Enabled = false
	}
	extra, err := domain.CompilePatterns(h.Filter.ExtraPatterns)
	if err != nil {
		return h, res, err
	}
	filtered := domain.Filter(res.Stdout, cfg, extra)
	res.Stdout = filtered.Text
	res.Filtered = cfg.Enabled
	res.DroppedLines = filtered.Dropped
	return h, res, nil
}

// TestConnection verifies reachability and authentication without running a
// user command. Connection-level retries live inside the client; this layer
// only bounds the total time.
func TestConnection(ctx context.Context, store HostStore, secrets SecretResolver, factory ClientFactory, name string, timeout time.Duration) (domain.Host, domain.TestResult, error) {
	if name == "" {
		return domain.Host{}, domain.TestResult{}, domain.Fail(domain.CodeInvalidInput, "host name must not be empty")
	}
	hosts, err := store.Load()
	if err != nil {
		return domain.Host{}, domain.TestResult{}, domain.Fail(domain.CodeStoreError, "cannot load host store: "+err.Error())
	}
	h, exists := hosts[name]
	if !exists {
		return domain.Host{}, domain.TestResult{}, domain.Fail(domain.CodeHostNotFound, "host "+name+" not found")
	}
	password, err := secrets.Resolve(h)
	if err != nil {
		return h, domain.TestResult{}, err
	}
	client, err := factory.NewClient(h, password)
	if err != nil {
		return h, domain.TestResult{}, err
	}
	defer client.Close()

	callCtx, cancel := context.WithTimeout(ctx, timeoutOrDefault(timeout))
	defer cancel()
	res, err := client.Test(callCtx)
	if err != nil {
		return h, res, err
	}
	return h, res, nil
}
