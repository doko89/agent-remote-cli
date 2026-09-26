package cli

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"agent-remote/internal/domain"
)

// maxInlineScript bounds the script size (before base64) so the generated
// command stays within WinRM's ~8 KB command-line limit after encoding.
const maxInlineScript = 4 * 1024

func scriptUsage() string {
	return `usage: script <name[,name...]> | --group G | --all [flags] -- <local_script> [args...]

  Pipe a local script to remote hosts via base64 — no temp files.
  Interpreter is auto-detected from the shebang (bash, sh, python3,
  node, ruby). Override with --interpreter.

Flags:
  --interpreter CMD      override shebang-detected interpreter (e.g. python3)
  --timeout DUR          execution timeout (default 30s)
  --parallel N           fan-out concurrency (default 4, max 64)
  --fail-fast            stop scheduling new hosts after first failure
  --no-filter            disable banner filtering
  --password-stdin       one-shot password from stdin
  --password-env VAR     one-shot password from environment`
}

func runScript(args []string, opt Options, d Deps) Outcome {
	left, right, ok := splitCommand(args)
	if !ok {
		return fail(domain.Fail(domain.CodeInvalidInput, scriptUsage()))
	}
	if len(right) == 0 {
		return fail(domain.Fail(domain.CodeInvalidInput, "script path must not be empty"))
	}
	scriptPath, scriptArgs := right[0], right[1:]
	content, interpreter, err := readScript(scriptPath)
	if err != nil {
		return fail(err)
	}
	exec, err := parseScriptFlags(left, content, interpreter, scriptArgs)
	if err != nil {
		return fail(err)
	}
	targets, err := resolveExecTargets(d.Store, *exec)
	if err != nil {
		return fail(err)
	}
	if len(targets) != 1 || exec.targeting {
		return runFanout(d, targets, exec.options(), exec.parallel, exec.failFast,
			overrideSecrets(d, opt, exec.pwStdin, exec.pwEnv))
	}
	return runSingleExec(d, opt, targets[0].Name, *exec)
}

// readScript reads a local file and detects the interpreter from its
// shebang. Returns the raw content and the interpreter command.
func readScript(path string) ([]byte, string, error) {
	content, err := os.ReadFile(path) //nolint:gosec // intentional: reads the user-supplied script path
	if err != nil {
		return nil, "", domain.Fail(domain.CodeInvalidInput, "cannot read script: "+err.Error())
	}
	if len(content) > maxInlineScript {
		return nil, "", domain.Fail(domain.CodeInvalidInput,
			fmt.Sprintf("script is %d bytes; max inline is %d — use cp + exec for large files", len(content), maxInlineScript))
	}
	return content, detectInterpreter(content), nil
}

// detectInterpreter parses the shebang line to determine the interpreter.
// Falls back to bash for scripts without a recognizable shebang.
func detectInterpreter(content []byte) string {
	if len(content) < 3 || content[0] != '#' || content[1] != '!' {
		return "bash"
	}
	line := strings.TrimSpace(string(content[:min(indexByte(content, '\n'), len(content))]))
	parts := strings.Fields(line[2:])
	if len(parts) == 0 {
		return "bash"
	}
	// `#!/usr/bin/env python3` → take the last field as the interpreter.
	interpreter := parts[len(parts)-1]
	// `#!/bin/bash` → take the basename.
	if idx := strings.LastIndex(interpreter, "/"); idx >= 0 {
		interpreter = interpreter[idx+1:]
	}
	if interpreter == "" {
		return "bash"
	}
	return interpreter
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return len(b)
}

// parseScriptFlags builds the exec flags for a script run. It extends
// parseExecFlags with interpreter detection and script argument passing.
func parseScriptFlags(left []string, content []byte, interpreter string, scriptArgs []string) (*execFlags, error) {
	// Temporarily inject `--interpreter` into the flag parsing by pre-parsing
	// left for the interpreter override.
	trimmed, override := extractInterpreter(left)
	if override != "" {
		interpreter = override
	}
	e, err := parseExecFlags(trimmed, []string{buildScriptCommand(content, interpreter, scriptArgs)})
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// extractInterpreter pulls the --interpreter flag value from left args,
// removing it so parseExecFlags doesn't choke on an unknown flag.
func extractInterpreter(left []string) ([]string, string) {
	var cleaned []string
	override := ""
	skip := false
	for _, a := range left {
		if skip {
			override = a
			skip = false
			continue
		}
		if a == "--interpreter" {
			skip = true
			continue
		}
		if strings.HasPrefix(a, "--interpreter=") {
			override = strings.TrimPrefix(a, "--interpreter=")
			continue
		}
		cleaned = append(cleaned, a)
	}
	return cleaned, override
}

// buildScriptCommand constructs the remote command that pipes the base64
// script into the interpreter, appending any extra script arguments.
func buildScriptCommand(content []byte, interpreter string, scriptArgs []string) string {
	b64 := base64.StdEncoding.EncodeToString(content)
	cmd := fmt.Sprintf("echo '%s' | base64 -d | %s", b64, interpreter)
	if len(scriptArgs) > 0 {
		cmd += " " + strings.Join(scriptArgs, " ")
	}
	return cmd
}
