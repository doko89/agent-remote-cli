// Command agent-remote runs one remote command or host-management action.
//
// This file is the composition root: the only place that imports
// infrastructure packages. Use cases never see concrete types.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"agent-remote/internal/adapter/cli"
	"agent-remote/internal/adapter/presenter"
	"agent-remote/internal/domain"
	"agent-remote/internal/infrastructure/configstore"
	"agent-remote/internal/infrastructure/secret"
	"agent-remote/internal/infrastructure/sshclient"
	"agent-remote/internal/infrastructure/sshmux"
	"agent-remote/internal/infrastructure/winrmclient"
	"agent-remote/internal/usecase"
)

// version is overridden at build time: -ldflags "-X main.version=...".
var version = "dev"

// factory routes to the protocol client. Adding a protocol means adding one
// case here; domain and use cases stay untouched (PRD 7.5 / 8).
type factory struct {
	ssh   sshclient.Factory
	winrm winrmclient.Factory
}

func (f factory) NewClient(h domain.Host, password string) (usecase.RemoteClient, error) {
	switch h.Protocol {
	case domain.ProtocolSSH:
		return f.ssh.NewClient(h, password)
	case domain.ProtocolWinRM:
		return f.winrm.NewClient(h, password)
	default:
		return nil, domain.Fail(domain.CodeInvalidInput, "unsupported protocol")
	}
}

func (f factory) NewTransferClient(h domain.Host, password string) (usecase.TransferClient, error) {
	switch h.Protocol {
	case domain.ProtocolSSH:
		return sshclient.SFTPFactory{DialTimeout: f.ssh.DialTimeout}.NewTransferClient(h, password)
	case domain.ProtocolWinRM:
		return winrmclient.WinRMFactory{DialTimeout: f.winrm.DialTimeout}.NewTransferClient(h, password)
	default:
		return nil, domain.Fail(domain.CodeInvalidInput, "unsupported protocol")
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if sshmux.ServeEnv() {
		return runMuxServe()
	}
	opt := cli.Options{Stdin: os.Stdin, Version: version}
	// Pre-read the config override so the store path is final before wiring.
	// cli.Run re-parses globals idempotently; unknown-flag tolerance here
	// keeps pre-scan from rejecting valid invocations.
	cfgPath := preScanConfig(args)
	if cfgPath == "" {
		p, err := configstore.DefaultPath()
		if err != nil {
			return emit(cli.Options{Version: version}, cli.Outcome{
				ToolErr: domain.Fail(domain.CodeStoreError, "cannot resolve config path: "+err.Error()),
			})
		}
		cfgPath = p
	}
	muxTTL, muxDisabled, err := preScanMux(args)
	if err != nil {
		return emit(cli.Options{Version: version}, cli.Outcome{
			ToolErr: domain.Fail(domain.CodeInvalidInput, err.Error()),
		})
	}
	var hub *sshmux.Hub
	if !muxDisabled {
		hub = sshmux.NewHub()
	}
	d := cli.Deps{
		Store:   configstore.Store{Path: cfgPath},
		Secrets: &secret.Resolver{},
		Factory: factory{
			ssh: sshclient.Factory{
				DialTimeout: 15 * time.Second,
				Hub:         hub,
				SpawnMaster: func(h domain.Host) {
					_ = sshmux.SpawnServe(h.Name, muxTTL)
				},
			},
			winrm: winrmclient.Factory{DialTimeout: 15 * time.Second},
		},
		TFactory: factory{ssh: sshclient.Factory{DialTimeout: 15 * time.Second}, winrm: winrmclient.Factory{DialTimeout: 15 * time.Second}},
	}
	out, opt := cli.Run(args, opt, d)
	return emit(opt, out)
}

// runMuxServe is the detached ControlPersist child: dial the host, serve its
// mux socket until the idle TTL, then exit quietly.
func runMuxServe() int {
	name := sshmux.ServeHost()
	ttl := sshmux.ServeTTL()
	if ttl <= 0 {
		ttl = sshmux.DefaultTTL
	}
	store := configstore.Store{Path: preScanConfig(os.Args[1:])}
	if p, err := configstore.DefaultPath(); err == nil && store.Path == "" {
		store.Path = p
	}
	hosts, err := store.Load()
	if err != nil {
		return 2
	}
	h, ok := hosts[name]
	if !ok {
		return 2
	}
	pw, err := (&secret.Resolver{}).Resolve(h)
	if err != nil {
		return 2
	}
	conn, banner, err := sshclient.NewRawClient(h, pw, 15*time.Second)
	if err != nil {
		return 2
	}
	hub := sshmux.NewHub()
	if err := hub.Offer(h, conn, banner, ttl); err != nil {
		conn.Close()
		return 0 // another master owns the socket; nothing to do
	}
	hub.Wait()
	return 0
}

// emit renders the outcome. JSON (default) always goes to stdout as one
// envelope so agents parse a single stream; --raw splits human text across
// stdout/stderr by convention.
func emit(opt cli.Options, out cli.Outcome) int {
	if !opt.Raw {
		if out.ToolErr != nil {
			fmt.Println(presenter.JSONError(out.ToolErr, opt.Pretty))
		} else {
			fmt.Println(presenter.JSON(out.Data, opt.Pretty))
		}
		return out.ExitCode()
	}
	if out.ToolErr != nil {
		fmt.Fprintln(os.Stderr, "error: "+out.ToolErr.Error())
		return out.ExitCode()
	}
	if out.RawOut != "" {
		fmt.Println(out.RawOut)
	}
	if out.RawErr != "" {
		fmt.Fprintln(os.Stderr, out.RawErr)
	}
	return out.ExitCode()
}

func preScanConfig(args []string) string {
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			return args[i+1]
		}
		if len(a) > 9 && a[:9] == "--config=" {
			return a[9:]
		}
	}
	return ""
}

// preScanMux mirrors the config pre-scan: global mux flags may appear before
// or after the command word, so scan raw argv before wiring the factory.
func preScanMux(args []string) (ttl time.Duration, disabled bool, err error) {
	ttl = sshmux.DefaultTTL
	for i, a := range args {
		if a == "--" {
			break // remote command content is off-limits to flag pre-scan
		}
		if a == "--no-mux" {
			disabled = true
			continue
		}
		val := ""
		switch {
		case a == "--mux-ttl" && i+1 < len(args):
			val = args[i+1]
		case strings.HasPrefix(a, "--mux-ttl="):
			val = strings.TrimPrefix(a, "--mux-ttl=")
		default:
			continue
		}
		d, perr := time.ParseDuration(val)
		if perr != nil || d <= 0 {
			return 0, false, fmt.Errorf("invalid --mux-ttl %q: use e.g. 10m", val)
		}
		ttl = d
	}
	return ttl, disabled, nil
}
