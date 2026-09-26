package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

// runSync implements: sync [--delete | --half] [-w] [--interval 5s] <src> <dest>
// Sides share cp's [host:]path syntax. Default is half side (one-way, never
// deletes); --delete switches to everything mode (deletions propagate).
// -w watches until interrupted, streaming one JSON object per applied action.
func runSync(args []string, opt Options, d Deps) Outcome {
	if wantsHelp(args) {
		return Outcome{RawOut: syncUsage(), Data: map[string]any{"help": syncUsage()}}
	}
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	del := fs.Bool("delete", false, "")
	half := fs.Bool("half", false, "")
	watch := fs.Bool("w", false, "")
	fs.BoolVar(watch, "watch", false, "")
	interval := fs.Duration("interval", 5*time.Second, "")
	timeout := fs.Duration("timeout", 10*time.Minute, "")
	parallel := fs.Int("parallel", 4, "parallel file transfers for directory scans")
	pwStdin := fs.Bool("password-stdin", false, "")
	pwEnv := fs.String("password-env", "", "")
	if err := fs.Parse(args); err != nil || len(fs.Args()) != 2 {
		return fail(domain.Fail(domain.CodeInvalidInput, syncUsage()))
	}
	if *del && *half {
		return fail(domain.Fail(domain.CodeInvalidInput, "--delete and --half exclude each other"))
	}
	if *timeout <= 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "timeout must be positive"))
	}
	if *parallel < 1 || *parallel > 64 {
		return fail(domain.Fail(domain.CodeInvalidInput, "parallel must be between 1 and 64"))
	}
	if *watch && *interval <= 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "interval must be positive"))
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
	mode := "half"
	if *del {
		mode = "everything"
	}
	req := usecase.SyncRequest{
		SrcHost: srcHost, SrcPath: srcPath, DstHost: dstHost, DstPath: dstPath,
		Opt: usecase.SyncOptions{Delete: *del, Timeout: *timeout, Concurrency: *parallel},
	}
	secrets := overrideSecrets(d, opt, *pwStdin, *pwEnv)
	if !*watch {
		res, err := usecase.SyncOneShot(context.Background(), d.Store, secrets, d.TFactory, req)
		if err != nil {
			return fail(err)
		}
		return syncOutcome(pos, mode, res)
	}
	return runWatch(d, opt, secrets, pos, mode, req, *interval)
}

// runWatch loops scans until interrupted, streaming each applied action.
func runWatch(d Deps, opt Options, secrets usecase.SecretResolver, pos []string, mode string, req usecase.SyncRequest, interval time.Duration) Outcome {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	printEvent := func(ev usecase.SyncEvent) {
		if opt.Raw {
			fmt.Printf("%s %s\n", ev.Op, ev.Path)
			return
		}
		raw, _ := json.Marshal(map[string]any{"event": ev.Op, "path": ev.Path, "bytes": ev.Bytes})
		fmt.Println(string(raw))
	}
	res, err := usecase.Watch(ctx, d.Store, secrets, d.TFactory, req, interval,
		func(ev usecase.SyncEvent) { printEvent(ev) })
	if err != nil {
		return fail(err)
	}
	out := syncOutcome(pos, mode, res)
	out.RemoteRan = false
	return out
}

func syncOutcome(pos []string, mode string, res usecase.SyncResult) Outcome {
	raw := fmt.Sprintf("synced %d file(s), %d byte(s), %d deleted [%s]: %s -> %s",
		res.Files, res.Bytes, res.Deleted, mode, pos[0], pos[1])
	return Outcome{
		Data: map[string]any{
			"src": pos[0], "dest": pos[1], "mode": mode,
			"files": res.Files, "bytes": res.Bytes, "deleted": res.Deleted,
			"scans": res.Scans, "duration_ms": res.DurationMs,
		},
		RawOut: raw,
	}
}

func syncUsage() string {
	return `usage: sync [--delete | --half] [-w] [--interval 5s] [--timeout 10m] [--parallel 4] <src> <dest>

  One-way mirror src onto dest (new + changed files copy over).
  Sides share cp's [host:]path syntax.

  --half     half-side mode: never delete (this is the default)
  --delete   everything mode: also delete dest files missing on src
  -w, --watch
             keep running until interrupted; rescan every --interval and
             stream one JSON object per applied action
  --parallel N  concurrent file transfers per scan (default 4, max 64)`
}
