package usecase

import (
	"context"
	"time"

	"agent-remote/internal/domain"
)

// RemoteFile describes one remote directory entry. Path is always the full
// remote path, joined by the client that listed it (remote separators differ
// per OS, so the use case never joins remote paths itself).
type RemoteFile struct {
	Path  string
	IsDir bool
	Size  int64
}

// TransferClient is per-host file access behind `cp`. Transfers stream in
// blocks chosen by the use case; each method maps to cheap primitives on
// both SFTP and WinRM (chunked PowerShell) so no side needs shell tricks.
type TransferClient interface {
	Stat(ctx context.Context, path string) (RemoteFile, error)
	// ReadDir lists one level; entries carry full remote paths.
	ReadDir(ctx context.Context, path string) ([]RemoteFile, error)
	MkdirAll(ctx context.Context, path string) error
	// ReadAt reads up to n bytes; short/empty return means EOF.
	ReadAt(ctx context.Context, path string, offset int64, n int) ([]byte, error)
	// AppendChunk writes data; first truncates/creates the destination.
	AppendChunk(ctx context.Context, path string, data []byte, first bool) error
	// Finalize completes an uploaded file (e.g. decoding staged text into
	// bytes on WinRM). No-op where AppendChunk lands directly.
	Finalize(ctx context.Context, path string) error
	// Parent returns the containing directory of a remote path.
	Parent(path string) string
	Close() error
}

// NewTransferClienter builds a file-transfer client for a host.
type NewTransferClienter interface {
	NewTransferClient(h domain.Host, password string) (TransferClient, error)
}

// Copy block size and default timeout. Blocks are small enough for WinRM
// command limits after base64 expansion, large enough to keep SFTP fast.
const (
	copyBlockSize     = 256 * 1024
	copyDefaultTimout = 10 * time.Minute
)
