package domain

import (
	"testing"
)

func TestFilterDropsBannerLines(t *testing.T) {
	in := "Last login: Thu Sep 25 10:00:00 2026 from 10.0.0.2\n" +
		"Welcome to Ubuntu 24.04 LTS\n" +
		"3 packages can be updated.\n" +
		"2 updates are security updates.\n" +
		"hello world\n"
	got := Filter(in, FilterConfig{Enabled: true}, nil)
	if got.Text != "hello world\n" {
		t.Fatalf("unexpected filtered text: %q", got.Text)
	}
	if got.Dropped != 4 {
		t.Fatalf("expected 4 dropped lines, got %d", got.Dropped)
	}
}

func TestFilterKeepsLegitOutput(t *testing.T) {
	in := "total 3\ndrwxr-xr-x 2 u g 4096 Sep 25 .\n"
	got := Filter(in, FilterConfig{Enabled: true}, nil)
	if got.Text != in || got.Dropped != 0 {
		t.Fatalf("legit output altered: %q dropped=%d", got.Text, got.Dropped)
	}
}

func TestFilterDisabledIsIdentity(t *testing.T) {
	in := "Last login: yesterday\nWelcome to FooOS\nreal\n"
	got := Filter(in, FilterConfig{Enabled: false}, nil)
	if got.Text != in || got.Dropped != 0 {
		t.Fatalf("disabled filter must not touch text: %q dropped=%d", got.Text, got.Dropped)
	}
}

func TestFilterCustomPatterns(t *testing.T) {
	extra, err := CompilePatterns([]string{`^COMPLIANCE-.*`})
	if err != nil {
		t.Fatal(err)
	}
	in := "COMPLIANCE-notice 42\nreal\n"
	got := Filter(in, FilterConfig{Enabled: true}, extra)
	if got.Text != "real\n" || got.Dropped != 1 {
		t.Fatalf("custom pattern not applied: %q dropped=%d", got.Text, got.Dropped)
	}
}

func TestFilterPreservesNoTrailingNewline(t *testing.T) {
	got := Filter("a\nb", FilterConfig{Enabled: true}, nil)
	if got.Text != "a\nb" {
		t.Fatalf("newline invented: %q", got.Text)
	}
}

func TestCompilePatternsRejectsBadRegex(t *testing.T) {
	if _, err := CompilePatterns([]string{`([`}); err == nil {
		t.Fatal("expected error for invalid regex")
	} else if CodeOf(err) != CodeInvalidInput {
		t.Fatalf("expected invalid_input code, got %q", CodeOf(err))
	}
}

// TestDefaultsNoFalsePositives guards the built-ins against eating legit
// command output. A pattern that matches ordinary output is a bug here.
func TestDefaultsNoFalsePositives(t *testing.T) {
	legit := []string{
		"total 42",
		"drwxr-xr-x 2 deploy deploy 4096 Sep 25 .",
		"200 OK",
		"last modified: yesterday", // must not trip ^last login:
		"package.json",
		"mailbox size 3", // must not trip mail notice
	}
	for _, line := range legit {
		if matchesAny(line, compiledDefaults) {
			t.Fatalf("default pattern eats legit line %q", line)
		}
	}
}
