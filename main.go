// Command agent-remote runs one remote command or host-management action.
//
// This file is the composition root: the only place that imports
// infrastructure packages. Use cases never see concrete types.
package main

import (
	"fmt"
	"os"

	"agent-remote/internal/adapter/cli"
	"agent-remote/internal/adapter/presenter"
	"agent-remote/internal/domain"
	"agent-remote/internal/infrastructure/configstore"
	"agent-remote/internal/infrastructure/secret"
	"agent-remote/internal/infrastructure/sshclient"
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

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
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
	d := cli.Deps{
		Store:   configstore.Store{Path: cfgPath},
		Secrets: &secret.Resolver{},
		Factory: factory{},
	}
	out, opt := cli.Run(args, opt, d)
	return emit(opt, out)
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
