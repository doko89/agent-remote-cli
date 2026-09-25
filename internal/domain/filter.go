package domain

import (
	"regexp"
	"strings"
)

// defaultPatterns are the built-in Lapis-2 banner/MOTD line patterns.
// Each must compile; they are matched case-insensitively per line.
var defaultPatterns = []string{
	`^last login:.*`,                                              // OpenSSH "Last login:" line
	`^welcome to .*`,                                              // distro welcome lines
	`.*\bpackages? can be updated\.?`,                             // apt update summary
	`.*\bupdates? (are|is) security updates?\.?`,                  // apt security summary
	`^you have (new )?mail\.?`,                                    // shell mail notice
	`.*\bunauthorized access\b.*`,                                 // compliance banners
	`.*\bauthorized users? only\b.*`,                              // compliance banners
	`.*\ball activity (may be|is|will be) (monitored|logged)\b.*`, // monitoring notice
}

var compiledDefaults = mustCompileAll(defaultPatterns)

func mustCompileAll(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(`(?i)`+p))
	}
	return out
}

// CompilePatterns validates user-supplied regexes up front so a bad pattern
// is rejected at `add` time, not felt at `exec` time.
func CompilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		r, err := regexp.Compile(`(?i)` + p)
		if err != nil {
			return nil, Fail(CodeInvalidInput, "invalid filter pattern "+quote(p)+": "+err.Error())
		}
		out = append(out, r)
	}
	return out, nil
}

// Filtered holds one filtered stream: kept text plus drop statistics.
type Filtered struct {
	Text    string
	Dropped int
}

// Filter applies Lapis-2 line filtering to one output stream.
// When cfg.Enabled is false the input is returned untouched, so callers can
// implement --no-filter by flipping one field.
func Filter(text string, cfg FilterConfig, extra []*regexp.Regexp) Filtered {
	if !cfg.Enabled {
		return Filtered{Text: text}
	}
	patterns := compiledDefaults
	if len(extra) > 0 {
		joined := make([]*regexp.Regexp, 0, len(patterns)+len(extra))
		joined = append(joined, patterns...)
		joined = append(joined, extra...)
		patterns = joined
	}
	// Preserve a trailing newline: Split would otherwise fabricate an
	// extra empty "line" that then round-trips into an extra newline.
	trailing := strings.HasSuffix(text, "\n")
	lines := strings.Split(text, "\n")
	kept := make([]string, 0, len(lines))
	dropped := 0
	for i, ln := range lines {
		if trailing && i == len(lines)-1 {
			continue // artifact of Split, not a real line
		}
		if matchesAny(ln, patterns) {
			dropped++
			continue
		}
		kept = append(kept, ln)
	}
	out := strings.Join(kept, "\n")
	if trailing && len(kept) > 0 {
		out += "\n"
	}
	return Filtered{Text: out, Dropped: dropped}
}

func matchesAny(line string, patterns []*regexp.Regexp) bool {
	for _, r := range patterns {
		if r.MatchString(line) {
			return true
		}
	}
	return false
}

func quote(s string) string {
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return "`" + s + "`"
}
