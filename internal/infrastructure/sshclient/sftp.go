package sshclient

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

// SFTPFactory builds file-transfer clients over the SSH SFTP subsystem.
type SFTPFactory struct {
	// DialTimeout bounds TCP connect + handshake per attempt.
	DialTimeout time.Duration
}

// NewTransferClient dials a dedicated connection and opens SFTP on it.
// A separate connection keeps transfers isolated from exec sessions.
func (f SFTPFactory) NewTransferClient(h domain.Host, password string) (usecase.TransferClient, error) {
	conn, _, err := dial(h, password, f.DialTimeout)
	if err != nil {
		return nil, err
	}
	sc, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, domain.Fail(domain.CodeConnectionFailed, "cannot open sftp subsystem: "+err.Error())
	}
	return &sftpClient{conn: conn, sftp: sc}, nil
}

type sftpClient struct {
	conn *ssh.Client
	sftp *sftp.Client

	// open holds one write handle per destination path. Handles stay open
	// across AppendChunk calls so chunk order never depends on O_APPEND,
	// which remote servers honor inconsistently.
	mu   sync.Mutex
	open map[string]*sftp.File
}

func (c *sftpClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p, f := range c.open {
		f.Close()
		delete(c.open, p)
	}
	c.sftp.Close()
	return c.conn.Close()
}

func (c *sftpClient) Stat(ctx context.Context, p string) (usecase.RemoteFile, error) {
	fi, err := c.sftp.Stat(p)
	if err != nil {
		return usecase.RemoteFile{}, sftpErr("stat", p, err)
	}
	return usecase.RemoteFile{Path: p, IsDir: fi.IsDir(), Size: fi.Size(), ModTime: fi.ModTime().UTC()}, nil
}

func (c *sftpClient) ReadDir(ctx context.Context, p string) ([]usecase.RemoteFile, error) {
	fis, err := c.sftp.ReadDir(p)
	if err != nil {
		return nil, sftpErr("list", p, err)
	}
	out := make([]usecase.RemoteFile, 0, len(fis))
	for _, fi := range fis {
		out = append(out, usecase.RemoteFile{Path: path.Join(p, fi.Name()), IsDir: fi.IsDir(), Size: fi.Size(), ModTime: fi.ModTime().UTC()})
	}
	return out, nil
}

// Remove deletes one file or empty directory.
func (c *sftpClient) Remove(ctx context.Context, p string) error {
	if err := c.sftp.Remove(p); err != nil {
		// Regular Remove fails on directories; retry as rmdir.
		if c.sftp.RemoveDirectory(p) != nil {
			return sftpErr("remove", p, err)
		}
	}
	return nil
}

// SetMTime stamps a written file so later sync scans compare correctly.
func (c *sftpClient) SetMTime(ctx context.Context, p string, mt time.Time) error {
	if err := c.sftp.Chtimes(p, mt, mt); err != nil {
		return sftpErr("chtimes", p, err)
	}
	return nil
}

func (c *sftpClient) MkdirAll(ctx context.Context, p string) error {
	if err := c.sftp.MkdirAll(p); err != nil {
		return sftpErr("mkdir", p, err)
	}
	return nil
}

func (c *sftpClient) ReadAt(ctx context.Context, p string, offset int64, n int) ([]byte, error) {
	f, err := c.sftp.Open(p)
	if err != nil {
		return nil, sftpErr("open", p, err)
	}
	defer f.Close()
	buf := make([]byte, n)
	m, rerr := readAtLeast(f, buf, offset)
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return nil, domain.Fail(domain.CodeConnectionFailed, fmt.Sprintf("sftp read %q: %s", p, rerr.Error()))
	}
	return buf[:m], nil
}

func readAtLeast(f *sftp.File, buf []byte, offset int64) (int, error) {
	total := 0
	for total < len(buf) {
		m, err := f.ReadAt(buf[total:], offset+int64(total))
		total += m
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (c *sftpClient) AppendChunk(ctx context.Context, p string, data []byte, first bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.open[p]
	if f == nil || first {
		if f != nil {
			f.Close()
			delete(c.open, p)
		}
		var err error
		f, err = c.sftp.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return sftpErr("open", p, err)
		}
		if c.open == nil {
			c.open = map[string]*sftp.File{}
		}
		c.open[p] = f
	}
	if _, err := f.Write(data); err != nil {
		return domain.Fail(domain.CodeConnectionFailed, fmt.Sprintf("sftp write %q: %s", p, err.Error()))
	}
	return nil
}

func (c *sftpClient) Parent(p string) string {
	return path.Dir(p)
}

// Finalize is a no-op for SFTP: AppendChunk lands bytes directly.
func (c *sftpClient) Finalize(context.Context, string) error { return nil }

func sftpErr(op, p string, err error) error {
	msg := err.Error()
	lower := strings.ToLower(msg)
	for _, s := range []string{"not found", "no such file", "does not exist", "enoent"} {
		if strings.Contains(lower, s) {
			return domain.Fail(domain.CodeInvalidInput, fmt.Sprintf("sftp %s %q: no such file", op, p))
		}
	}
	return domain.Fail(domain.CodeConnectionFailed, fmt.Sprintf("sftp %s %q: %s", op, p, msg))
}
