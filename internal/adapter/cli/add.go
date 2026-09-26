package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"agent-remote/internal/domain"
	"agent-remote/internal/infrastructure/secret"
	"agent-remote/internal/usecase"
)

// stringList is a repeatable --filter-pattern flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type addFlags struct {
	host     string
	port     int
	user     string
	auth     string
	authRef  string
	passEnv  string
	pwStdin  bool
	pwEnv    string
	patterns stringList
	noFilter bool
	group    string

	transport string
	insecure  bool
}

func runAdd(args []string, opt Options, d Deps) Outcome {
	if len(args) == 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "usage: add <ssh|winrm> <name> [options]"))
	}
	proto, rest := args[0], args[1:]
	switch proto {
	case "ssh":
		return runAddProto(domain.ProtocolSSH, rest, opt, d)
	case "winrm":
		return runAddProto(domain.ProtocolWinRM, rest, opt, d)
	default:
		return fail(domain.Fail(domain.CodeInvalidInput,
			fmt.Sprintf("unknown protocol %q; use `add ssh` or `add winrm`", proto)))
	}
}

func addFlagSet(proto domain.Protocol, args []string) (*flag.FlagSet, *addFlags, []string, error) {
	f := &addFlags{}
	fs := flag.NewFlagSet("add "+string(proto), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&f.host, "host", "", "remote address (required)")
	fs.StringVar(&f.user, "user", "", "login username (required)")
	fs.StringVar(&f.auth, "auth", "keyring", "secret source: keyring | env | stdin | keyfile (ssh only)")
	fs.StringVar(&f.authRef, "auth-ref", "", "env var name (auth=env) or private key path (auth=keyfile)")
	fs.StringVar(&f.passEnv, "passphrase-env", "", "env var with the key passphrase (ssh keyfile only)")
	fs.StringVar(&f.group, "group", "", "optional fan-out target label")
	fs.BoolVar(&f.pwStdin, "password-stdin", false, "read the keyring secret from stdin at add time")
	fs.StringVar(&f.pwEnv, "password-env", "", "read the keyring secret from $VAR at add time")
	fs.Var(&f.patterns, "filter-pattern", "extra banner-filter regex (repeatable)")
	fs.BoolVar(&f.noFilter, "no-filter", false, "disable banner filtering for this host")
	if proto == domain.ProtocolSSH {
		fs.IntVar(&f.port, "port", 22, "ssh port")
	} else {
		fs.IntVar(&f.port, "port", 5985, "winrm port")
		fs.StringVar(&f.transport, "transport", "http", "winrm transport: http | https")
		fs.BoolVar(&f.insecure, "insecure", false, "skip TLS verification (https only)")
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, domain.Fail(domain.CodeInvalidInput, addUsage(proto))
	}
	return fs, f, fs.Args(), nil
}

func runAddProto(proto domain.Protocol, args []string, opt Options, d Deps) Outcome {
	if wantsHelp(args) {
		return Outcome{RawOut: addUsage(proto), Data: map[string]any{"help": addUsage(proto)}}
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fail(domain.Fail(domain.CodeInvalidInput, addUsage(proto)))
	}
	name := protoName(args[0])
	if name == "" {
		return fail(domain.Fail(domain.CodeInvalidInput, addUsage(proto)))
	}
	_, f, pos, err := addFlagSet(proto, args[1:])
	if err != nil {
		return fail(err)
	}
	if len(pos) != 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, addUsage(proto)))
	}
	in := usecase.AddHostInput{
		Name: name, Protocol: proto,
		Address: f.host, Port: f.port, User: f.user,
		Auth: domain.AuthMethod(strings.ToLower(f.auth)), AuthRef: f.authRef,
		Group:               f.group,
		PassphraseEnv:       f.passEnv,
		WinRMTransport:      f.transport,
		WinRMInsecure:       f.insecure,
		ExtraFilterPatterns: []string(f.patterns),
		FilterDisabled:      f.noFilter,
	}
	// Secret-supply flags only make sense when the secret is stored now.
	if in.Auth != domain.AuthKeyring && (f.pwStdin || f.pwEnv != "") {
		return fail(domain.Fail(domain.CodeInvalidInput,
			"--password-stdin/--password-env at add time are only for auth=keyring; use them with exec/test for one-shot overrides"))
	}
	var keyringPw string
	if in.Auth == domain.AuthKeyring {
		pw, err := addTimeSecret(opt, f)
		if err != nil {
			return fail(err)
		}
		keyringPw = pw
	}
	h, err := usecase.AddHost(d.Store, in)
	if err != nil {
		return fail(err)
	}
	if in.Auth == domain.AuthKeyring {
		if err := secret.Save(h.Name, keyringPw); err != nil {
			_ = usecase.RemoveHost(d.Store, d.Secrets, h.Name) // rollback: no orphan host
			return fail(err)
		}
	}
	raw := fmt.Sprintf("added host %s (%s %s@%s:%d)", h.Name, h.Protocol, h.User, h.Address, h.DefaultPort())
	return Outcome{Data: map[string]any{"added": h.Name}, RawOut: raw}
}

// addTimeSecret reads the to-be-stored keyring password from stdin or env.
// Exactly one source is required: a keyring entry with no secret is a trap
// that only explodes later at exec time.
func addTimeSecret(opt Options, f *addFlags) (string, error) {
	switch {
	case f.pwStdin && f.pwEnv != "":
		return "", domain.Fail(domain.CodeInvalidInput, "use only one of --password-stdin or --password-env")
	case f.pwStdin:
		return readPipePassword(opt.Stdin)
	case f.pwEnv != "":
		if v, ok := os.LookupEnv(f.pwEnv); ok {
			return v, nil
		}
		return "", domain.Fail(domain.CodeSecretUnavailable,
			fmt.Sprintf("environment variable %s is not set", f.pwEnv))
	default:
		return "", domain.Fail(domain.CodeInvalidInput,
			"auth=keyring requires the secret now: pass --password-stdin or --password-env")
	}
}

func protoName(s string) string { return strings.TrimSpace(s) }

func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}

// readPipePassword consumes a piped password, refusing to block on a TTY.
func readPipePassword(stdin io.Reader) (string, error) {
	src := stdin
	if src == nil {
		src = os.Stdin
	}
	if f, ok := src.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			return "", domain.Fail(domain.CodeSecretUnavailable,
				"password over stdin requires a pipe; refusing to block on a TTY")
		}
	}
	raw, err := io.ReadAll(src)
	if err != nil {
		return "", domain.Fail(domain.CodeSecretUnavailable, "cannot read password from stdin: "+err.Error())
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

func usage(version string) string {
	return fmt.Sprintf(`agent-remote %s — uniform SSH/WinRM command runner for agents.

USAGE
  agent-remote [--config PATH] [--raw] [--pretty] <command> [options]

CONNECTION REUSE (SSH)
  Repeated exec/test reuse one authenticated connection (ControlPersist
  style). --no-mux disables it; --mux-ttl DUR sets the idle linger time.

COMMANDS
  add ssh <name> [options]     register a new SSH host
  add winrm <name> [options]   register a new WinRM host
  rm <name>                    remove a host and its stored secret
  rename <old> <new>           rename a host (moves its stored secret)
  group <list|rename|move|remove>
                               manage fan-out target groups
  list                         list hosts (never shows secrets)
  show <name>                  show one host (never shows secrets)
  test <name> [--timeout 30s]  handshake-only connectivity check
  exec <name[,name...]> | --group G | --all
                               [--timeout 30s] [--parallel 4] [--fail-fast]
                               [--no-filter] [--login] -- <command...>
                               run a remote command (banner-filtered);
                               --login wraps it in 'bash -lic' so the full
                               user profile PATH applies (still no PTY;
                               bash may log 2 job-control warnings to
                               stderr because there is no TTY)
  cp [-r] [options] <src> <dest>
                               copy files ([host:]path, local when bare)
  sync [options] <src> <dest>  mirror src onto dest (half side default,
                               --delete for everything, -w to watch)

OUTPUT
  Default is a single-line JSON envelope {"ok","data","error"} for every
  command. --raw switches to human-readable text; --pretty indents JSON.
  Filtering (--no-filter) and format (--raw) are independent settings.

EXIT CODES
  0  success (remote command exited 0)
  1  remote command ran and exited non-zero
  2  tool failure (see error.code: host_not_found, auth_failed, ...)

SECRETS
  Passwords are never CLI flag values. At add time store one with
  --password-stdin (pipe) or --password-env VAR (auth=keyring), or reference
  one per-run with --password-env VAR (auth=env). exec/test accept
  --password-stdin / --password-env as a one-shot override without storing.

See: agent-remote add ssh --help | agent-remote add winrm --help`, version)
}

func addUsage(proto domain.Protocol) string {
	if proto == domain.ProtocolSSH {
		return `usage: add ssh <name> --host ADDR --user USER [options]

  --port INT               ssh port (default 22)
  --auth METHOD            keyring (default) | env | stdin | keyfile
  --auth-ref REF           env var name (auth=env) or key path (auth=keyfile)
  --passphrase-env VAR     env var with the key passphrase (auth=keyfile)
  --group LABEL            optional label for exec --group
  --password-stdin         read keyring secret from stdin now (auth=keyring)
  --password-env VAR       read keyring secret from $VAR now (auth=keyring)
  --filter-pattern REGEX   extra banner-filter regex (repeatable)
  --no-filter              disable banner filtering for this host`
	}
	return `usage: add winrm <name> --host ADDR --user USER [options]

  --port INT               winrm port (default 5985)
  --transport T            http (default) | https
  --insecure               skip TLS verification (https only)
  --auth METHOD            keyring (default) | env | stdin
  --auth-ref REF           env var name (auth=env)
  --group LABEL            optional label for exec --group
  --password-stdin         read keyring secret from stdin now (auth=keyring)
  --password-env VAR       read keyring secret from $VAR now (auth=keyring)
  --filter-pattern REGEX   extra banner-filter regex (repeatable)
  --no-filter              disable banner filtering for this host

Remote commands run via PowerShell.`
}
