package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

// runCp implements: cp [-r] [--timeout 10m] <src> <dest>
// Each side is `[host:]path`: a `host:` prefix names a registered host,
// a bare path is local. A colon with an unknown host is rejected instead of
// silently treated as a local filename.
func runCp(args []string, opt Options, d Deps) Outcome {
	if wantsHelp(args) {
		return Outcome{RawOut: cpUsage(), Data: map[string]any{"help": cpUsage()}}
	}
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	recursive := fs.Bool("r", false, "")
	fs.BoolVar(recursive, "recursive", false, "")
	timeout := fs.Duration("timeout", 10*time.Minute, "")
	pwStdin := fs.Bool("password-stdin", false, "")
	pwEnv := fs.String("password-env", "", "")
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 2 {
		return fail(domain.Fail(domain.CodeInvalidInput, cpUsage()))
	}
	if *timeout <= 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "timeout must be positive"))
	}
	pos := fs.Args()
	srcHost, srcPath, err := splitRef(d, pos[0])
	if err != nil {
		return fail(err)
	}
	dstHost, dstPath, err := splitRef(d, pos[1])
	if err != nil {
		return fail(err)
	}
	res, err := usecase.Copy(context.Background(), d.Store, overrideSecrets(d, opt, *pwStdin, *pwEnv), d.TFactory,
		usecase.CopyRequest{
			SrcHost: srcHost, SrcPath: srcPath, DstHost: dstHost, DstPath: dstPath,
			Opt: usecase.CopyOptions{Recursive: *recursive, Timeout: *timeout},
		})
	if err != nil {
		return fail(err)
	}
	raw := fmt.Sprintf("copied %d file(s), %d byte(s): %s -> %s", res.Files, res.Bytes, pos[0], pos[1])
	return Outcome{
		Data: map[string]any{
			"src": pos[0], "dest": pos[1],
			"files": res.Files, "bytes": res.Bytes, "duration_ms": res.DurationMs,
		},
		RawOut: raw,
	}
}

// splitRef resolves one cp side into (hostName, path). Empty host means local.
func splitRef(d Deps, arg string) (string, string, error) {
	idx := strings.Index(arg, ":")
	if idx < 0 {
		if arg == "" {
			return "", "", domain.Fail(domain.CodeInvalidInput, "empty path")
		}
		return "", arg, nil
	}
	name, path := arg[:idx], arg[idx+1:]
	if name == "" || path == "" {
		return "", "", domain.Fail(domain.CodeInvalidInput, fmt.Sprintf("bad location %q: use [host:]path", arg))
	}
	hosts, err := d.Store.Load()
	if err != nil {
		return "", "", domain.Fail(domain.CodeStoreError, "cannot load host store: "+err.Error())
	}
	if _, ok := hosts[name]; !ok {
		return "", "", domain.Fail(domain.CodeHostNotFound, fmt.Sprintf("host %s not found", name))
	}
	return name, path, nil
}

func cpUsage() string {
	return `usage: cp [-r] [--timeout 10m] [--password-stdin | --password-env VAR] <src> <dest>

  Each side is [host:]path: a host: prefix names a registered host,
  a bare path is local. Examples:
    cp report.txt w45:C:/temp/        upload to WinRM host
    cp w45:C:/temp/report.txt .        download from WinRM host
    cp -r ./dist web1:/opt/app         recursive upload to SSH host
    cp web1:/var/log/app.log w45:C:/t/ remote-to-remote (via local temp)

  -r  copy directories recursively (required for directory sources)`
}
