package presenter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"agent-remote/internal/domain"
)

func TestErrorEnvelopeCarriesStableCode(t *testing.T) {
	out := JSONError(domain.Fail(domain.CodeAuthFailed, "nope"), false)
	var env struct {
		OK    bool `json:"ok"`
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	if env.OK || env.Error.Code != "auth_failed" || env.Error.Message != "nope" {
		t.Fatalf("bad envelope: %s", out)
	}
	if !strings.HasSuffix(out, "}") || strings.Contains(out, "\n") {
		t.Fatalf("default JSON must be single-line: %q", out)
	}
}

func TestPlainErrorMapsToInternal(t *testing.T) {
	out := JSONError(errors.New("kaboom"), false)
	if !strings.Contains(out, `"code":"internal"`) {
		t.Fatalf("expected internal code: %s", out)
	}
}

func TestRawListAndShow(t *testing.T) {
	if RawList(nil) != "no hosts configured" {
		t.Fatalf("empty list text: %q", RawList(nil))
	}
	hosts := []domain.Host{
		{Name: "b", Protocol: domain.ProtocolSSH, Address: "h", User: "u", Filter: domain.DefaultFilter()},
		{Name: "a", Protocol: domain.ProtocolWinRM, Address: "h2", User: "u2", Auth: domain.AuthEnv, AuthRef: "V", Filter: domain.DefaultFilter()},
	}
	list := RawList(hosts)
	if len(list) == 0 || list[0] != 'a' {
		t.Fatalf("list must be sorted by name: %q", list)
	}
	show := RawShow(hosts[0])
	for _, want := range []string{"name:      b", "protocol:  ssh", "port:      22", "filter:    enabled"} {
		if !strings.Contains(show, want) {
			t.Fatalf("show missing %q in:\n%s", want, show)
		}
	}
}

func TestRawShowFullHost(t *testing.T) {
	h := domain.Host{
		Name: "w", Protocol: domain.ProtocolWinRM, Address: "h", Port: 5986,
		User: "u", Auth: domain.AuthEnv, AuthRef: "V", PassphraseEnv: "P",
		WinRMTransport: "https", WinRMInsecure: true,
		Filter: domain.FilterConfig{Enabled: false, ExtraPatterns: []string{"^X"}},
	}
	show := RawShow(h)
	for _, want := range []string{"auth_ref:  V", "passphrase_env: P", "transport: https", "insecure:  true", "filter:    disabled", "pattern:   ^X", "port:      5986"} {
		if !strings.Contains(show, want) {
			t.Fatalf("show missing %q in:\n%s", want, show)
		}
	}
}

func TestJSONPretty(t *testing.T) {
	out := JSON(map[string]any{"a": 1}, true)
	if !strings.Contains(out, "\n") || !strings.Contains(out, `"ok": true`) {
		t.Fatalf("pretty JSON wrong: %q", out)
	}
}

func TestHostViewHidesSecrets(t *testing.T) {
	h := domain.Host{Name: "w", Protocol: domain.ProtocolSSH, Address: "h",
		Port: 22, User: "u", Auth: domain.AuthKeyring, Filter: domain.DefaultFilter()}
	raw, _ := json.Marshal(ViewHost(h))
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		s := strings.ToLower(k + strings.TrimSpace(strings.ToLower(jsonString(v))))
		if strings.Contains(s, "password") || strings.Contains(s, "secret") {
			t.Fatalf("secret-looking content in host view: %s", raw)
		}
	}
}

func jsonString(v any) string {
	s, _ := v.(string)
	return s
}
