package usecase

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"agent-remote/internal/domain"
)

// CopyOptions tunes one `cp` invocation.
type CopyOptions struct {
	Recursive bool
	Timeout   time.Duration
}

// CopyRequest is one `cp` invocation: both endpoints plus options.
type CopyRequest struct {
	SrcHost, SrcPath string
	DstHost, DstPath string
	Opt              CopyOptions
}

// dirNeedsFlag rejects directory sources without recursive mode.
const dirNeedsFlag = "source is a directory; pass -r for recursive copy"

// timedOut reports a copy stopped by its deadline.
const timedOut = "copy timed out"

// CopyResult counts what one `cp` moved.
type CopyResult struct {
	Files      int64
	Bytes      int64
	DurationMs int64
}

// Copy moves one file or tree between local and remote sides. Either side is
// local when its host name is empty. Remote-to-remote always routes through
// a local temp file, so every protocol combination behaves identically.
func Copy(ctx context.Context, store HostStore, secrets SecretResolver, factory NewTransferClienter, req CopyRequest) (CopyResult, error) {
	var res CopyResult
	if req.SrcHost == "" && req.DstHost == "" {
		return res, domain.Fail(domain.CodeInvalidInput, "both sides are local; use cp")
	}
	if req.SrcPath == "" || req.DstPath == "" {
		return res, domain.Fail(domain.CodeInvalidInput, "source and destination paths must not be empty")
	}
	if req.SrcHost == req.DstHost && req.SrcPath == req.DstPath {
		return res, domain.Fail(domain.CodeInvalidInput, "source and destination are the same")
	}
	hosts, err := store.Load()
	if err != nil {
		return res, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	src, err := resolveSide(hosts, req.SrcHost)
	if err != nil {
		return res, err
	}
	dst, err := resolveSide(hosts, req.DstHost)
	if err != nil {
		return res, err
	}
	timeout := copyDefaultTimout
	if req.Opt.Timeout > 0 {
		timeout = req.Opt.Timeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	c, err := newCopier(callCtx, secrets, factory, src, dst)
	if err != nil {
		return res, err
	}
	defer c.close()
	if err := c.copy(callCtx, src, req.SrcPath, dst, req.DstPath, req.Opt.Recursive, &res); err != nil {
		return res, err
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

func resolveSide(hosts map[string]domain.Host, name string) (*domain.Host, error) {
	if name == "" {
		return nil, nil
	}
	h, exists := hosts[name]
	if !exists {
		return nil, domain.Fail(domain.CodeHostNotFound, "host "+name+" not found")
	}
	return &h, nil
}

// copier holds the open transfer clients for one Copy call.
type copier struct {
	clients map[string]TransferClient
}

func newCopier(ctx context.Context, secrets SecretResolver, factory NewTransferClienter, src, dst *domain.Host) (*copier, error) {
	c := &copier{clients: map[string]TransferClient{}}
	for _, h := range []*domain.Host{src, dst} {
		if h == nil {
			continue
		}
		if _, ok := c.clients[h.Name]; ok {
			continue
		}
		password, err := secrets.Resolve(*h)
		if err != nil {
			c.close()
			return nil, err
		}
		client, err := factory.NewTransferClient(*h, password)
		if err != nil {
			c.close()
			return nil, err
		}
		c.clients[h.Name] = client
	}
	return c, nil
}

func (c *copier) close() {
	for _, client := range c.clients {
		client.Close()
	}
}

// copy dispatches on the four side combinations.
func (c *copier) copy(ctx context.Context, src *domain.Host, srcPath string, dst *domain.Host, dstPath string, recursive bool, res *CopyResult) error {
	switch {
	case src == nil:
		return c.upload(ctx, srcPath, dst, dstPath, recursive, res)
	case dst == nil:
		return c.download(ctx, src, srcPath, dstPath, recursive, res)
	default:
		return c.relay(ctx, src, srcPath, dst, dstPath, recursive, res)
	}
}

// upload copies a local file or tree to a remote destination.
func (c *copier) upload(ctx context.Context, localPath string, dst *domain.Host, dstPath string, recursive bool, res *CopyResult) error {
	d := c.clients[dst.Name]
	info, err := os.Stat(localPath)
	if err != nil {
		return domain.Fail(domain.CodeInvalidInput, "cannot stat local path: "+err.Error())
	}
	if info.IsDir() {
		if !recursive {
			return domain.Fail(domain.CodeInvalidInput, dirNeedsFlag)
		}
		return c.uploadDir(ctx, d, localPath, dstPath, res)
	}
	return c.uploadFile(ctx, d, localPath, dstPath, res)
}

func (c *copier) uploadFile(ctx context.Context, d TransferClient, localPath, dstPath string, res *CopyResult) error {
	if err := d.MkdirAll(ctx, d.Parent(dstPath)); err != nil {
		return err
	}
	f, err := os.Open(localPath)
	if err != nil {
		return domain.Fail(domain.CodeInvalidInput, "cannot open local file: "+err.Error())
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return domain.Fail(domain.CodeInternal, "cannot stat local file: "+err.Error())
	}
	if fi.Size() == 0 {
		// No chunks will flow; still materialize the empty file, then
		// finalize (decodes staging where the protocol stages).
		if err := d.AppendChunk(ctx, dstPath, nil, true); err != nil {
			return err
		}
		if err := d.Finalize(ctx, dstPath); err != nil {
			return err
		}
		res.Files++
		return nil
	}
	if err := c.streamToRemote(ctx, d, f, dstPath, res); err != nil {
		return err
	}
	return d.Finalize(ctx, dstPath)
}

func (c *copier) uploadDir(ctx context.Context, d TransferClient, localDir, dstDir string, res *CopyResult) error {
	if err := d.MkdirAll(ctx, dstDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return domain.Fail(domain.CodeInvalidInput, "cannot list local directory: "+err.Error())
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return domain.Fail(domain.CodeTimeout, timedOut)
		}
		lp := filepath.Join(localDir, e.Name())
		dst := dstChild(dstDir, e.Name())
		if e.IsDir() {
			if err := c.uploadDir(ctx, d, lp, dst, res); err != nil {
				return err
			}
			continue
		}
		if err := c.uploadFile(ctx, d, lp, dst, res); err != nil {
			return err
		}
	}
	return nil
}

// download copies a remote file or tree to a local destination.
func (c *copier) download(ctx context.Context, src *domain.Host, srcPath, localPath string, recursive bool, res *CopyResult) error {
	s := c.clients[src.Name]
	info, err := s.Stat(ctx, srcPath)
	if err != nil {
		return err
	}
	if info.IsDir {
		if !recursive {
			return domain.Fail(domain.CodeInvalidInput, dirNeedsFlag)
		}
		return c.downloadDir(ctx, s, srcPath, localPath, res)
	}
	return c.downloadFile(ctx, s, srcPath, localPath, res)
}

func (c *copier) downloadFile(ctx context.Context, s TransferClient, srcPath, localPath string, res *CopyResult) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return domain.Fail(domain.CodeInvalidInput, "cannot create local directory: "+err.Error())
	}
	f, err := os.Create(localPath)
	if err != nil {
		return domain.Fail(domain.CodeInvalidInput, "cannot create local file: "+err.Error())
	}
	defer f.Close()
	return c.streamFromRemote(ctx, s, srcPath, f, res)
}

func (c *copier) downloadDir(ctx context.Context, s TransferClient, srcDir, localDir string, res *CopyResult) error {
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return domain.Fail(domain.CodeInvalidInput, "cannot create local directory: "+err.Error())
	}
	entries, err := s.ReadDir(ctx, srcDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return domain.Fail(domain.CodeTimeout, timedOut)
		}
		lp := filepath.Join(localDir, remoteBase(e.Path))
		if e.IsDir {
			if err := c.downloadDir(ctx, s, e.Path, lp, res); err != nil {
				return err
			}
			continue
		}
		if err := c.downloadFile(ctx, s, e.Path, lp, res); err != nil {
			return err
		}
	}
	return nil
}

// relay routes remote-to-remote through local staging. The download phase
// counts into a scratch result; only the upload phase counts for real, so
// each file is counted exactly once.
func (c *copier) relay(ctx context.Context, src *domain.Host, srcPath string, dst *domain.Host, dstPath string, recursive bool, res *CopyResult) error {
	s := c.clients[src.Name]
	d := c.clients[dst.Name]
	info, err := s.Stat(ctx, srcPath)
	if err != nil {
		return err
	}
	if info.IsDir && !recursive {
		return domain.Fail(domain.CodeInvalidInput, dirNeedsFlag)
	}
	var scratch CopyResult
	if info.IsDir {
		tmpDir, err := os.MkdirTemp("", "agent-remote-cp-*")
		if err != nil {
			return domain.Fail(domain.CodeInternal, "cannot create temp dir: "+err.Error())
		}
		defer os.RemoveAll(tmpDir)
		if err := c.downloadDir(ctx, s, srcPath, tmpDir, &scratch); err != nil {
			return err
		}
		return c.uploadDir(ctx, d, tmpDir, dstPath, res)
	}
	tmp, err := os.CreateTemp("", "agent-remote-cp-*")
	if err != nil {
		return domain.Fail(domain.CodeInternal, "cannot create temp file: "+err.Error())
	}
	tmpName := tmp.Name()
	if err := c.streamFromRemote(ctx, s, srcPath, tmp, &scratch); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()
	defer os.Remove(tmpName)
	return c.uploadStagedFile(ctx, d, tmpName, dstPath, res)
}

// uploadStagedFile uploads a temp file staged by relay and counts it.
func (c *copier) uploadStagedFile(ctx context.Context, d TransferClient, tmpName, dstPath string, res *CopyResult) error {
	f, err := os.Open(tmpName)
	if err != nil {
		return domain.Fail(domain.CodeInternal, "cannot open temp file: "+err.Error())
	}
	defer f.Close()
	if err := d.MkdirAll(ctx, d.Parent(dstPath)); err != nil {
		return err
	}
	if err := c.streamToRemote(ctx, d, f, dstPath, res); err != nil {
		return err
	}
	return d.Finalize(ctx, dstPath)
}

// streamToRemote copies one open local file to a remote path.
func (c *copier) streamToRemote(ctx context.Context, d TransferClient, f *os.File, dstPath string, res *CopyResult) error {
	first := true
	buf := make([]byte, copyBlockSize)
	for {
		if err := ctx.Err(); err != nil {
			return domain.Fail(domain.CodeTimeout, timedOut)
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := d.AppendChunk(ctx, dstPath, buf[:n], first); err != nil {
				return err
			}
			first = false
			res.Bytes += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return domain.Fail(domain.CodeInternal, "cannot read local file: "+rerr.Error())
		}
	}
	res.Files++
	return nil
}

// streamFromRemote copies one remote file to an open local file.
func (c *copier) streamFromRemote(ctx context.Context, s TransferClient, srcPath string, f *os.File, res *CopyResult) error {
	var offset int64
	for {
		if err := ctx.Err(); err != nil {
			return domain.Fail(domain.CodeTimeout, timedOut)
		}
		chunk, err := s.ReadAt(ctx, srcPath, offset, copyBlockSize)
		if err != nil {
			return err
		}
		if len(chunk) == 0 {
			break
		}
		if _, err := f.Write(chunk); err != nil {
			return domain.Fail(domain.CodeInternal, "cannot write local file: "+err.Error())
		}
		offset += int64(len(chunk))
		res.Bytes += int64(len(chunk))
		if len(chunk) < copyBlockSize {
			break
		}
	}
	res.Files++
	return nil
}

// dstChild joins a child name onto a remote dir. Both supported systems
// accept "/" (PowerShell too), so one form suffices for every client.
func dstChild(dir, name string) string {
	return dir + "/" + name
}

// remoteBase is the last segment of a remote path on either separator.
func remoteBase(p string) string {
	if i := lastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func lastIndexAny(s, chars string) int {
	for i := len(s) - 1; i >= 0; i-- {
		for j := 0; j < len(chars); j++ {
			if s[i] == chars[j] {
				return i
			}
		}
	}
	return -1
}
