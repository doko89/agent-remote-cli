package domain

// Code is a stable machine-readable error identifier for the JSON envelope.
// AI agents branch on Code, never on Message text.
type Code string

const (
	CodeOK                Code = ""
	CodeHostNotFound      Code = "host_not_found"
	CodeHostExists        Code = "host_exists"
	CodeInvalidInput      Code = "invalid_input"
	CodeStoreError        Code = "store_error"
	CodeAuthFailed        Code = "auth_failed"
	CodeConnectionFailed  Code = "connection_failed"
	CodeTimeout           Code = "timeout"
	CodeSecretUnavailable Code = "secret_unavailable"
	CodeRemoteFailed      Code = "remote_failed"
	CodeInternal          Code = "internal"
)

// ToolError is a tool-level failure (as opposed to a remote command that
// simply exited non-zero). It carries a stable Code for machine consumers.
type ToolError struct {
	ErrCode Code
	Msg     string
}

func (e *ToolError) Error() string { return e.Msg }

// CodeOf extracts the machine-readable code from err, defaulting to internal.
func CodeOf(err error) Code {
	if err == nil {
		return CodeOK
	}
	if te, ok := err.(*ToolError); ok {
		return te.ErrCode
	}
	return CodeInternal
}

// Fail builds a tool-level error. Use Message for human context; agents key
// off ErrCode which must stay stable across versions.
func Fail(code Code, msg string) *ToolError {
	return &ToolError{ErrCode: code, Msg: msg}
}
