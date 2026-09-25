// Package presenter converts use-case outcomes into output bytes.
// JSON (default) always uses the envelope {ok, data, error}; --raw renders
// plain human-readable text. Banner filtering and format selection stay
// independent: this layer never touches filtering.
package presenter

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"agent-remote/internal/domain"
)

// Envelope is the uniform JSON wrapper for every command.
type Envelope struct {
	OK    bool     `json:"ok"`
	Data  any      `json:"data,omitempty"`
	Error *ErrBody `json:"error,omitempty"`
}

// ErrBody is the machine-readable error. Agents branch on Code.
type ErrBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// JSON renders v inside the success envelope.
func JSON(v any, pretty bool) string {
	return render(Envelope{OK: true, Data: v}, pretty)
}

// JSONError renders err inside the failure envelope with a stable code.
func JSONError(err error, pretty bool) string {
	code := string(domain.CodeOf(err))
	if code == "" {
		code = string(domain.CodeInternal)
	}
	msg := "internal error"
	if err != nil {
		msg = err.Error()
	}
	return render(Envelope{OK: false, Error: &ErrBody{Code: code, Message: msg}}, pretty)
}

func render(env Envelope, pretty bool) string {
	var raw []byte
	var err error
	if pretty {
		raw, err = json.MarshalIndent(env, "", "  ")
	} else {
		raw, err = json.Marshal(env)
	}
	if err != nil {
		return `{"ok":false,"error":{"code":"internal","message":"cannot encode output"}}`
	}
	return string(raw)
}

// HostView is the secret-free public projection of a host.
type HostView struct {
	Name           string   `json:"name"`
	Protocol       string   `json:"protocol"`
	Address        string   `json:"address"`
	Port           int      `json:"port"`
	User           string   `json:"user"`
	Auth           string   `json:"auth"`
	AuthRef        string   `json:"auth_ref,omitempty"`
	PassphraseEnv  string   `json:"passphrase_env,omitempty"`
	WinRMTransport string   `json:"winrm_transport,omitempty"`
	WinRMInsecure  bool     `json:"winrm_insecure,omitempty"`
	FilterEnabled  bool     `json:"filter_enabled"`
	FilterPatterns []string `json:"filter_patterns,omitempty"`
}

// ViewHost projects h without secrets (the type cannot carry them).
func ViewHost(h domain.Host) HostView {
	return HostView{
		Name:           h.Name,
		Protocol:       string(h.Protocol),
		Address:        h.Address,
		Port:           h.DefaultPort(),
		User:           h.User,
		Auth:           string(h.Auth),
		AuthRef:        h.AuthRef,
		PassphraseEnv:  h.PassphraseEnv,
		WinRMTransport: h.WinRMTransport,
		WinRMInsecure:  h.WinRMInsecure,
		FilterEnabled:  h.Filter.Enabled,
		FilterPatterns: h.Filter.ExtraPatterns,
	}
}

// ExecView is the JSON data body for `exec`.
type ExecView struct {
	Host          string `json:"host"`
	Command       string `json:"command"`
	Stdout        string `json:"stdout"`
	Stderr        string `json:"stderr"`
	ExitCode      int    `json:"exit_code"`
	DurationMs    int64  `json:"duration_ms"`
	Filtered      bool   `json:"filtered"`
	DroppedLines  int    `json:"dropped_lines"`
	PreAuthBanner string `json:"pre_auth_banner,omitempty"`
}

// TestView is the JSON data body for `test`.
type TestView struct {
	Host          string `json:"host"`
	Reachable     bool   `json:"reachable"`
	LatencyMs     int64  `json:"latency_ms"`
	PreAuthBanner string `json:"pre_auth_banner,omitempty"`
}

// RawList renders `list` for humans.
func RawList(hosts []domain.Host) string {
	if len(hosts) == 0 {
		return "no hosts configured"
	}
	names := make([]string, 0, len(hosts))
	for _, h := range hosts {
		names = append(names, h.Name)
	}
	sort.Strings(names)
	byName := map[string]domain.Host{}
	for _, h := range hosts {
		byName[h.Name] = h
	}
	var b strings.Builder
	for _, n := range names {
		h := byName[n]
		fmt.Fprintf(&b, "%s\t%s\t%s@%s:%d\n", h.Name, h.Protocol, h.User, h.Address, h.DefaultPort())
	}
	return strings.TrimRight(b.String(), "\n")
}

// RawShow renders `show` for humans.
func RawShow(h domain.Host) string {
	v := ViewHost(h)
	var b strings.Builder
	fmt.Fprintf(&b, "name:      %s\n", v.Name)
	fmt.Fprintf(&b, "protocol:  %s\n", v.Protocol)
	fmt.Fprintf(&b, "address:   %s\n", v.Address)
	fmt.Fprintf(&b, "port:      %d\n", v.Port)
	fmt.Fprintf(&b, "user:      %s\n", v.User)
	fmt.Fprintf(&b, "auth:      %s\n", v.Auth)
	if v.AuthRef != "" {
		fmt.Fprintf(&b, "auth_ref:  %s\n", v.AuthRef)
	}
	if v.PassphraseEnv != "" {
		fmt.Fprintf(&b, "passphrase_env: %s\n", v.PassphraseEnv)
	}
	if v.WinRMTransport != "" {
		fmt.Fprintf(&b, "transport: %s\n", v.WinRMTransport)
		if v.WinRMInsecure {
			fmt.Fprintf(&b, "insecure:  true\n")
		}
	}
	fmt.Fprintf(&b, "filter:    %s\n", enabledWord(v.FilterEnabled))
	for _, p := range v.FilterPatterns {
		fmt.Fprintf(&b, "pattern:   %s\n", p)
	}
	return strings.TrimRight(b.String(), "\n")
}

func enabledWord(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}
