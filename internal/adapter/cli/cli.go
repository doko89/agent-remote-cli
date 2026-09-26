// Package cli parses argv into use-case calls. Each add subcommand exposes
// only the flags valid for its protocol (PRD 5.1), and the remote command of
// `exec` is always split off at an explicit `--` separator (PRD 5.3).
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"agent-remote/internal/adapter/presenter"
	"agent-remote/internal/domain"
	"agent-remote/internal/infrastructure/secret"
	"agent-remote/internal/usecase"
)

// Exit codes (PRD 5.3, open question 2 resolved):
// 0 = success (remote command exited 0, or management command ok).
// 1 = the remote command ran and exited non-zero (its streams are data).
// 2 = tool-level failure (usage, store, connect, auth, timeout, secret).
const (
	ExitOK       = 0
	ExitRemoteKo = 1
	ExitToolFail = 2
)

// Options are process-wide settings from global flags and the environment.
type Options struct {
	ConfigPath string
	Raw        bool
	Pretty     bool
	NoMux      bool
	Stdin      io.Reader
	Version    string
}

// Deps wires the ports. Assembled once in main (composition root).
type Deps struct {
	Store    usecase.HostStore
	Secrets  SecretStorer
	Factory  usecase.NewClienter
	TFactory usecase.NewTransferClienter
}

// SecretStorer is the secret port plus keyring persistence for `add`.
type SecretStorer interface {
	usecase.SecretResolver
}

// Outcome is the single result main renders and exits with.
type Outcome struct {
	Data       any    // JSON envelope body on success
	RawOut     string // stdout text in --raw mode
	RawErr     string // stderr text in --raw mode
	ToolErr    error  // tool-level failure (exit 2)
	RemoteExit int    // remote exit code when RemoteRan
	RemoteRan  bool
}

// ExitCode maps the outcome to the process status.
func (o Outcome) ExitCode() int {
	if o.ToolErr != nil {
		return ExitToolFail
	}
	if o.RemoteRan && o.RemoteExit != 0 {
		return ExitRemoteKo
	}
	return ExitOK
}

// Run dispatches argv (without the program name). It returns the effective
// options (global flags may appear before the command) alongside the outcome.
func Run(args []string, opt Options, d Deps) (Outcome, Options) {
	cmd, rest := shiftGlobal(args, &opt)
	out := dispatch(cmd, rest, opt, d)
	return out, opt
}

func dispatch(cmd string, rest []string, opt Options, d Deps) Outcome {
	switch cmd {
	case "add":
		return runAdd(rest, opt, d)
	case "rm":
		return runRm(rest, opt, d)
	case "rename":
		return runRename(rest, opt, d)
	case "list":
		return runList(rest, d)
	case "show":
		return runShow(rest, d)
	case "test":
		return runTest(rest, opt, d)
	case "exec":
		return runExec(rest, opt, d)
	case "cp":
		return runCp(rest, opt, d)
	case "sync":
		return runSync(rest, opt, d)
	case "help", "--help", "-h", "":
		return Outcome{RawOut: usage(opt.Version), Data: map[string]any{"help": usage(opt.Version)}}
	case "version", "--version":
		return Outcome{RawOut: opt.Version, Data: map[string]any{"version": opt.Version}}
	default:
		return fail(domain.Fail(domain.CodeInvalidInput,
			fmt.Sprintf("unknown command %q; see `help`", cmd)))
	}
}

func fail(err error) Outcome { return Outcome{ToolErr: err} }

// shiftGlobal extracts global flags given before the command, returning the
// command and the remaining args.
func shiftGlobal(args []string, opt *Options) (string, []string) {
	var rest []string
	cmd := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if cmd == "" && !strings.HasPrefix(a, "-") {
			cmd = a
			continue
		}
		if cmd == "" {
			switch {
			case a == "--raw":
				opt.Raw = true
			case a == "--pretty":
				opt.Pretty = true
			case a == "--no-mux":
				opt.NoMux = true
			case a == "--mux-ttl" && i+1 < len(args):
				i++
			case strings.HasPrefix(a, "--config="):
				opt.ConfigPath = strings.TrimPrefix(a, "--config=")
			case a == "--config" && i+1 < len(args):
				i++
				opt.ConfigPath = args[i]
			default:
				rest = append(rest, a)
			}
			continue
		}
		rest = append(rest, a)
	}
	return cmd, rest
}

func runRm(args []string, opt Options, d Deps) Outcome {
	fs, positional, err := parseSimple(args, "rm <name>", "remove a host and its stored secret")
	if err != nil {
		return fail(err)
	}
	_ = fs
	if len(positional) != 1 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: rm <name>"))
	}
	name := positional[0]
	if err := usecase.RemoveHost(d.Store, d.Secrets, name); err != nil {
		return fail(err)
	}
	return Outcome{
		Data:   map[string]any{"removed": name},
		RawOut: "removed host " + name,
	}
}

// runRename implements: rename <old> <new>. The stored keyring secret
// travels with the host; auth=env/stdin/keyfile references need no move.
// Order matters: the new keyring entry is written before the store rename
// so a keyring failure aborts with nothing changed, and a store failure
// rolls the new secret back.
func runRename(args []string, opt Options, d Deps) Outcome {
	_, positional, err := parseSimple(args, "rename <old> <new>", "")
	if err != nil {
		return fail(err)
	}
	if len(positional) != 2 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: rename <old> <new>"))
	}
	from, to := strings.TrimSpace(positional[0]), strings.TrimSpace(positional[1])
	if from == "" || to == "" || from == to {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: rename <old> <new> (names must differ and be non-empty)"))
	}
	var movedSecret bool
	if pw, lerr := secret.Load(from); lerr == nil {
		if serr := secret.Save(to, pw); serr != nil {
			return fail(serr)
		}
		movedSecret = true
	}
	h, rerr := usecase.RenameHost(d.Store, from, to)
	if rerr != nil {
		if movedSecret {
			secret.Delete(to)
		}
		return fail(rerr)
	}
	if movedSecret {
		secret.Delete(from)
	}
	return Outcome{
		Data:   map[string]any{"from": from, "to": to, "host": presenter.ViewHost(h)},
		RawOut: fmt.Sprintf("renamed host %s -> %s", from, to),
	}
}

func runList(args []string, d Deps) Outcome {
	if len(args) != 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: list (takes no arguments)"))
	}
	hosts, err := usecase.ListHosts(d.Store)
	if err != nil {
		return fail(err)
	}
	views := make([]presenter.HostView, 0, len(hosts))
	for _, h := range hosts {
		views = append(views, presenter.ViewHost(h))
	}
	return Outcome{
		Data:   map[string]any{"hosts": views},
		RawOut: presenter.RawList(hosts),
	}
}

func runShow(args []string, d Deps) Outcome {
	if len(args) != 1 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: show <name>"))
	}
	h, err := usecase.ShowHost(d.Store, args[0])
	if err != nil {
		return fail(err)
	}
	return Outcome{
		Data:   map[string]any{"host": presenter.ViewHost(h)},
		RawOut: presenter.RawShow(h),
	}
}

func runTest(args []string, opt Options, d Deps) Outcome {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: test <name> [--timeout 30s]"))
	}
	name, flagArgs := args[0], args[1:]
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", 30*time.Second, "")
	pwStdin := fs.Bool("password-stdin", false, "")
	pwEnv := fs.String("password-env", "", "")
	if err := fs.Parse(flagArgs); err != nil || len(fs.Args()) != 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: test <name> [--timeout 30s]"))
	}
	if *timeout <= 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "timeout must be positive"))
	}
	h, res, err := usecase.TestConnection(context.Background(), d.Store, overrideSecrets(d, opt, *pwStdin, *pwEnv), d.Factory, name, *timeout)
	if err != nil {
		return fail(err)
	}
	view := presenter.TestView{Host: h.Name, Reachable: res.Reachable, LatencyMs: res.LatencyMs, PreAuthBanner: res.PreAuthBanner}
	raw := fmt.Sprintf("host %s reachable (%dms)", h.Name, res.LatencyMs)
	return Outcome{Data: view, RawOut: raw}
}

func runExec(args []string, opt Options, d Deps) Outcome {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		return fail(domain.Fail(domain.CodeInvalidInput,
			"missing `--` separator: usage: exec <name> [--timeout 30s] [--no-filter] -- <command...>"))
	}
	left, remote := args[:sep], args[sep+1:]
	if len(remote) == 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "remote command must not be empty"))
	}
	if len(left) == 0 || strings.HasPrefix(left[0], "-") {
		return fail(domain.Fail(domain.CodeInvalidInput,
			"usage: exec <name> [--timeout 30s] [--no-filter] -- <command...>"))
	}
	name, leftFlags := left[0], left[1:]
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	timeout := fs.Duration("timeout", 30*time.Second, "")
	noFilter := fs.Bool("no-filter", false, "")
	pwStdin := fs.Bool("password-stdin", false, "")
	pwEnv := fs.String("password-env", "", "")
	if err := fs.Parse(leftFlags); err != nil || len(fs.Args()) != 0 {
		return fail(domain.Fail(domain.CodeInvalidInput,
			"usage: exec <name> [--timeout 30s] [--no-filter] -- <command...>"))
	}
	if *timeout <= 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "timeout must be positive"))
	}
	command := strings.Join(remote, " ")
	h, res, err := usecase.Exec(context.Background(), d.Store, overrideSecrets(d, opt, *pwStdin, *pwEnv), d.Factory, name,
		usecase.ExecOptions{Command: command, Timeout: *timeout, NoFilter: *noFilter})
	if err != nil {
		return fail(err)
	}
	view := presenter.ExecView{
		Host: h.Name, Command: command,
		Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.ExitCode,
		DurationMs: res.DurationMs, Filtered: res.Filtered,
		DroppedLines: res.DroppedLines, PreAuthBanner: res.PreAuthBanner,
	}
	return Outcome{Data: view, RawOut: res.Stdout, RawErr: res.Stderr, RemoteRan: true, RemoteExit: res.ExitCode}
}

// parseSimple is a minimal parser for commands with no flags.
func parseSimple(args []string, usageLine, _ string) (*flag.FlagSet, []string, error) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return nil, nil, domain.Fail(domain.CodeInvalidInput, "usage: "+usageLine)
		}
	}
	return nil, args, nil
}

// overrideSecrets wraps the secret port with a one-shot password source for
// exec/test. Without override flags the configured method is used unchanged.
func overrideSecrets(d Deps, opt Options, pwStdin bool, pwEnv string) usecase.SecretResolver {
	if !pwStdin && pwEnv == "" {
		return d.Secrets
	}
	return overrideResolver{base: d.Secrets, stdin: opt.Stdin, useStdin: pwStdin, envVar: pwEnv}
}

type overrideResolver struct {
	base     usecase.SecretResolver
	stdin    io.Reader
	useStdin bool
	envVar   string
}

func (o overrideResolver) Resolve(h domain.Host) (string, error) {
	if o.useStdin {
		return readPipePassword(o.stdin)
	}
	if v, ok := os.LookupEnv(o.envVar); ok {
		return v, nil
	}
	return "", domain.Fail(domain.CodeSecretUnavailable,
		fmt.Sprintf("environment variable %s is not set", o.envVar))
}

func (o overrideResolver) Delete(hostName string) error {
	return o.base.Delete(hostName)
}
