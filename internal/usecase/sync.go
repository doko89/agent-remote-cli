package usecase

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"time"

	"agent-remote/internal/domain"
)

// mtimeWindow tolerates clock skew and coarse filesystem granularity when
// deciding whether a same-size file changed. rsync calls this --modify-window.
const mtimeWindow = 2 * time.Second

// SyncOptions tunes one `sync` invocation.
type SyncOptions struct {
	// Delete propagates deletions (everything mode). Default (half side)
	// never deletes: extra destination files are left alone.
	Delete bool
	// Timeout bounds one scan; 0 means copyDefaultTimout. Watch cancels via ctx.
	Timeout time.Duration
	// OnEvent receives every applied action; nil disables the stream.
	OnEvent func(SyncEvent)
}

// SyncEvent is one applied sync action, streamed in watch mode.
type SyncEvent struct {
	Op    string // "copy" | "mkdir" | "delete"
	Path  string // destination-side full path
	Bytes int64  // copy only
}

// SyncResult counts one scan (one-shot) or the accumulated watch session.
type SyncResult struct {
	Files      int64
	Bytes      int64
	Deleted    int64
	Scans      int64
	DurationMs int64
}

func (r *SyncResult) addBytes(n int64) { r.Bytes += n }
func (r *SyncResult) addFile()         { r.Files++ }

// SyncRequest is one `sync` invocation: endpoints plus mode.
type SyncRequest struct {
	SrcHost, SrcPath string
	DstHost, DstPath string
	Opt              SyncOptions
}

// SyncOneShot mirrors src onto dst once: new and changed files copy over,
// deletions propagate only in everything mode (Opt.Delete).
func SyncOneShot(ctx context.Context, store HostStore, secrets SecretResolver, factory NewTransferClienter, req SyncRequest) (SyncResult, error) {
	var res SyncResult
	if req.SrcHost == "" && req.DstHost == "" {
		return res, domain.Fail(domain.CodeInvalidInput, "both sides are local; use rsync")
	}
	if req.SrcPath == "" || req.DstPath == "" {
		return res, domain.Fail(domain.CodeInvalidInput, "source and destination paths must not be empty")
	}
	if req.SrcHost == req.DstHost && req.SrcPath == req.DstPath {
		return res, domain.Fail(domain.CodeInvalidInput, "source and destination are the same")
	}
	timeout := copyDefaultTimout
	if req.Opt.Timeout > 0 {
		timeout = req.Opt.Timeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	s, err := newSyncer(callCtx, store, secrets, factory, req)
	if err != nil {
		return res, err
	}
	defer s.close()
	if err := s.scan(callCtx, &res, req.Opt); err != nil {
		return res, err
	}
	res.Scans = 1
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// Watch repeats scans every interval until ctx cancels (Ctrl-C). Each scan
// copies creates/updates (and deletes in everything mode); events stream
// through Opt.OnEvent. Cancellation between scans exits 0 with totals.
func Watch(ctx context.Context, store HostStore, secrets SecretResolver, factory NewTransferClienter, req SyncRequest, interval time.Duration, onEvent func(SyncEvent)) (SyncResult, error) {
	var total SyncResult
	if interval <= 0 {
		interval = 5 * time.Second
	}
	opt := req.Opt
	opt.Timeout = 0 // scans run unbounded; the session ends by cancel
	opt.OnEvent = onEvent
	start := time.Now()
	for {
		res, err := SyncOneShot(ctx, store, secrets, factory, SyncRequest{
			SrcHost: req.SrcHost, SrcPath: req.SrcPath,
			DstHost: req.DstHost, DstPath: req.DstPath, Opt: opt,
		})
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return total, err
		}
		total.Files += res.Files
		total.Bytes += res.Bytes
		total.Deleted += res.Deleted
		total.Scans++
		select {
		case <-ctx.Done():
			total.DurationMs = time.Since(start).Milliseconds()
			return total, nil
		case <-time.After(interval):
		}
	}
	total.DurationMs = time.Since(start).Milliseconds()
	return total, nil
}

// treeEntry is one side's file or dir, keyed by slash-relative path.
type treeEntry struct {
	rel   string
	full  string
	isDir bool
	size  int64
	mtime time.Time
}

// side is one sync endpoint: a nil host means local.
type side struct {
	host   *domain.Host
	root   string
	client TransferClient // nil when local
}

type syncer struct {
	copier *copier
	src    side
	dst    side
}

func newSyncer(ctx context.Context, store HostStore, secrets SecretResolver, factory NewTransferClienter, req SyncRequest) (*syncer, error) {
	hosts, err := store.Load()
	if err != nil {
		return nil, domain.Fail(domain.CodeStoreError, loadStoreErr+err.Error())
	}
	srcHost, err := resolveSide(hosts, req.SrcHost)
	if err != nil {
		return nil, err
	}
	dstHost, err := resolveSide(hosts, req.DstHost)
	if err != nil {
		return nil, err
	}
	c, err := newCopier(ctx, secrets, factory, srcHost, dstHost)
	if err != nil {
		return nil, err
	}
	clientOf := func(h *domain.Host) TransferClient {
		if h == nil {
			return nil
		}
		return c.clients[h.Name]
	}
	return &syncer{copier: c,
		src: side{srcHost, req.SrcPath, clientOf(srcHost)},
		dst: side{dstHost, req.DstPath, clientOf(dstHost)}}, nil
}

func (s *syncer) close() { s.copier.close() }

func (s *syncer) emit(opt SyncOptions, ev SyncEvent) {
	if opt.OnEvent != nil {
		opt.OnEvent(ev)
	}
}

// scan mirrors the source onto the destination once.
func (s *syncer) scan(ctx context.Context, res *SyncResult, opt SyncOptions) error {
	srcInfo, err := statSide(ctx, s.src, s.src.root)
	if err != nil {
		return err
	}
	if !srcInfo.isDir {
		return s.syncOneFile(ctx, s.src, s.src.root, srcInfo, s.dst, s.dst.root, res, opt)
	}
	if err := mkdirSide(ctx, s.dst, s.dst.root); err != nil {
		return err
	}
	srcTree, err := walkSide(ctx, s.src, s.src.root)
	if err != nil {
		return err
	}
	dstTree, err := walkSide(ctx, s.dst, s.dst.root)
	if err != nil {
		return err
	}
	for _, rel := range sortedKeys(srcTree) {
		if err := ctx.Err(); err != nil {
			return domain.Fail(domain.CodeTimeout, timedOut)
		}
		se := srcTree[rel]
		dstFull := joinSide(s.dst, rel)
		if se.isDir {
			if _, ok := dstTree[rel]; !ok {
				if err := mkdirSide(ctx, s.dst, dstFull); err != nil {
					return err
				}
				s.emit(opt, SyncEvent{Op: "mkdir", Path: dstFull})
			}
			continue
		}
		if de, ok := dstTree[rel]; ok && !de.isDir && sameContent(se, de) {
			continue
		}
		if de, ok := dstTree[rel]; ok && de.isDir {
			if err := removeTree(ctx, s.dst, de.full); err != nil {
				return err
			}
		}
		before := res.Bytes
		if err := s.copyFile(ctx, s.src, se.full, s.dst, dstFull, res); err != nil {
			return err
		}
		if err := stampSide(ctx, s.dst, dstFull, se.mtime); err != nil {
			return err
		}
		s.emit(opt, SyncEvent{Op: "copy", Path: dstFull, Bytes: res.Bytes - before})
	}
	if opt.Delete {
		for _, rel := range sortedKeysDesc(dstTree) {
			if _, ok := srcTree[rel]; ok {
				continue
			}
			if err := removeTree(ctx, s.dst, dstTree[rel].full); err != nil {
				return err
			}
			res.Deleted++
			s.emit(opt, SyncEvent{Op: "delete", Path: dstTree[rel].full})
		}
	}
	return nil
}

// syncOneFile syncs a single-file source onto a file destination path.
func (s *syncer) syncOneFile(ctx context.Context, src side, srcFull string, srcInfo treeEntry, dst side, dstFull string, res *SyncResult, opt SyncOptions) error {
	if de, err := statSide(ctx, dst, dstFull); err == nil {
		if de.isDir {
			return domain.Fail(domain.CodeInvalidInput, "destination is a directory but source is a file")
		}
		if sameContent(srcInfo, de) {
			return nil
		}
	} else if domain.CodeOf(err) != domain.CodeInvalidInput {
		return err
	}
	before := res.Bytes
	if err := s.copyFile(ctx, src, srcFull, dst, dstFull, res); err != nil {
		return err
	}
	if err := stampSide(ctx, dst, dstFull, srcInfo.mtime); err != nil {
		return err
	}
	s.emit(opt, SyncEvent{Op: "copy", Path: dstFull, Bytes: res.Bytes - before})
	return nil
}

// copyFile moves one file between any side combination, counting into res.
func (s *syncer) copyFile(ctx context.Context, src side, srcFull string, dst side, dstFull string, res *SyncResult) error {
	c := s.copier
	switch {
	case src.host == nil:
		return c.uploadFile(ctx, dst.client, srcFull, dstFull, res)
	case dst.host == nil:
		return c.downloadFile(ctx, src.client, srcFull, dstFull, res)
	default:
		return c.relay(ctx, src.host, srcFull, dst.host, dstFull, false, res)
	}
}

func sortedKeys(m map[string]treeEntry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedKeysDesc orders deepest paths first so deletes empty children
// before their parents.
func sortedKeysDesc(m map[string]treeEntry) []string {
	keys := sortedKeys(m)
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] > keys[j]
	})
	return keys
}

// statSide stats one path on either side.
func statSide(ctx context.Context, sd side, full string) (treeEntry, error) {
	if sd.host == nil {
		fi, err := os.Stat(full)
		if err != nil {
			return treeEntry{}, domain.Fail(domain.CodeInvalidInput, "cannot stat local path: "+err.Error())
		}
		return treeEntry{full: full, isDir: fi.IsDir(), size: fi.Size(), mtime: fi.ModTime().UTC()}, nil
	}
	rf, err := sd.client.Stat(ctx, full)
	if err != nil {
		return treeEntry{}, err
	}
	return treeEntry{full: rf.Path, isDir: rf.IsDir, size: rf.Size, mtime: rf.ModTime.UTC()}, nil
}

func mkdirSide(ctx context.Context, sd side, full string) error {
	if sd.host == nil {
		if err := os.MkdirAll(full, 0o755); err != nil {
			return domain.Fail(domain.CodeInvalidInput, "cannot create local directory: "+err.Error())
		}
		return nil
	}
	return sd.client.MkdirAll(ctx, full)
}

// walkSide lists a directory tree as slash-relative entries.
func walkSide(ctx context.Context, sd side, root string) (map[string]treeEntry, error) {
	out := map[string]treeEntry{}
	if sd.host == nil {
		err := filepath.WalkDir(root, func(full string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if full == root {
				return nil
			}
			rel, err := filepath.Rel(root, full)
			if err != nil {
				return err
			}
			var size int64
			var mt time.Time
			if !d.IsDir() {
				if info, err := d.Info(); err == nil {
					size, mt = info.Size(), info.ModTime().UTC()
				}
			}
			out[filepath.ToSlash(rel)] = treeEntry{rel: filepath.ToSlash(rel), full: full, isDir: d.IsDir(), size: size, mtime: mt}
			return nil
		})
		if err != nil {
			return nil, domain.Fail(domain.CodeInvalidInput, "cannot list local directory: "+err.Error())
		}
		return out, nil
	}
	type item struct {
		full string
		rel  string
	}
	queue := []item{{root, ""}}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, domain.Fail(domain.CodeTimeout, timedOut)
		}
		cur := queue[0]
		queue = queue[1:]
		entries, err := sd.client.ReadDir(ctx, cur.full)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			rel := remoteBase(e.Path)
			if cur.rel != "" {
				rel = cur.rel + "/" + rel
			}
			out[rel] = treeEntry{rel: rel, full: e.Path, isDir: e.IsDir, size: e.Size, mtime: e.ModTime.UTC()}
			if e.IsDir {
				queue = append(queue, item{e.Path, rel})
			}
		}
	}
	return out, nil
}

// joinSide appends a slash-relative path to a side root.
func joinSide(sd side, rel string) string {
	if sd.host == nil {
		return filepath.Join(sd.root, filepath.FromSlash(rel))
	}
	return dstChild(sd.root, rel)
}

// stampSide records the source mtime on a just-written destination file.
func stampSide(ctx context.Context, sd side, full string, mt time.Time) error {
	if mt.IsZero() {
		return nil
	}
	if sd.host == nil {
		if err := os.Chtimes(full, mt, mt); err != nil {
			return domain.Fail(domain.CodeInternal, "cannot stamp local file: "+err.Error())
		}
		return nil
	}
	return sd.client.SetMTime(ctx, full, mt)
}

// removeTree deletes one entry; directories recurse first.
func removeTree(ctx context.Context, sd side, full string) error {
	if sd.host == nil {
		if err := os.RemoveAll(full); err != nil {
			return domain.Fail(domain.CodeInternal, "cannot remove local path: "+err.Error())
		}
		return nil
	}
	// List children first so non-empty dirs empty before removal.
	var rec func(string) error
	rec = func(dir string) error {
		entries, err := sd.client.ReadDir(ctx, dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir {
				if err := rec(e.Path); err != nil {
					return err
				}
			} else if err := sd.client.Remove(ctx, e.Path); err != nil {
				return err
			}
		}
		return sd.client.Remove(ctx, dir)
	}
	info, err := sd.client.Stat(ctx, full)
	if err != nil {
		return err
	}
	if !info.IsDir {
		return sd.client.Remove(ctx, full)
	}
	return rec(full)
}

// sameContent reports whether the destination copy is fresh: same size, and
// mtimes within the skew window (or either side unknown, size decides).
func sameContent(src, dst treeEntry) bool {
	if src.size != dst.size {
		return false
	}
	if src.mtime.IsZero() || dst.mtime.IsZero() {
		return true
	}
	d := src.mtime.Sub(dst.mtime)
	if d < 0 {
		d = -d
	}
	return d <= mtimeWindow
}
