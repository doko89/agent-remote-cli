package domain

// ExecResult is the outcome of one remote command execution.
type ExecResult struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	DurationMs int64

	// Filtered reports whether Lapis-2 banner filtering was applied.
	Filtered bool
	// DroppedLines counts stdout lines removed by the filter.
	DroppedLines int
	// PreAuthBanner is an SSH pre-auth banner captured outside the
	// command streams. It is never merged into Stdout.
	PreAuthBanner string
}

// TestResult is the outcome of a side-effect-free connectivity check.
type TestResult struct {
	Reachable     bool
	LatencyMs     int64
	PreAuthBanner string
}
