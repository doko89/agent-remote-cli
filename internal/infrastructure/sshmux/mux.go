// Package sshmux implements SSH connection reuse across CLI invocations,
// mirroring OpenSSH ControlMaster/ControlPersist semantics. The first
// agent-remote invocation dials fresh, serves a unix socket, and lingers
// for the TTL after its command finishes; later invocations reuse the
// connection through the socket with no TCP/handshake/auth cost.
package sshmux

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"agent-remote/internal/domain"
	"agent-remote/internal/usecase"
)

// Environment variables driving a detached serve child. The child re-dials
// the host itself, owns the mux socket, and exits after the idle TTL.
const (
	envServe = "AGENT_REMOTE_MUX_SERVE"
	envHost  = "AGENT_REMOTE_MUX_HOST"
	envTTL   = "AGENT_REMOTE_MUX_TTL"
)

// DefaultTTL matches a ControlPersist 10m workflow: after the last command
// the master lingers ten minutes, then closes and removes its socket.
const DefaultTTL = 10 * time.Minute

// ErrMasterAlive is returned by Offer when another live master already
// serves the host; the fresh connection should be used and closed normally.
var ErrMasterAlive = errors.New("sshmux: master already alive")

// MuxError reports a mux transport failure. Sent marks the retry safety
// boundary: false means the request never reached the master process, so
// falling back to a fresh connection and re-running the command is safe;
// true means the master may have already executed it remotely, and a blind
// retry could repeat side effects.
type MuxError struct {
	Sent bool
	Err  error
}

func (e *MuxError) Error() string { return e.Err.Error() }

func (e *MuxError) Unwrap() error { return e.Err }

// request is one mux client command. An empty Command means "handshake
// probe": the server opens and closes a session to prove the connection.
type request struct {
	Command   string `json:"command"`
	TimeoutMs int64  `json:"timeout_ms"`
}

// response carries the exec result (or probe ack) back to the client.
type response struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	Banner    string `json:"banner,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	ErrorMsg  string `json:"error_msg,omitempty"`
}

// socketPath returns the unix socket path for one host, hashed so distinct
// hosts never collide and the name stays filesystem-safe.
func socketPath(dir string, h domain.Host) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", h.Name, h.User, h.Address, h.DefaultPort())))
	return filepath.Join(dir, "mux-"+hex.EncodeToString(sum[:8])+".sock")
}

// defaultDir mirrors the config store location ($AGENT_REMOTE_CONFIG's
// directory when set, else ~/.config/agent-remote).
func defaultDir() (string, error) {
	if p := os.Getenv("AGENT_REMOTE_CONFIG"); p != "" {
		return filepath.Dir(p), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "agent-remote"), nil
}

// Hub coordinates master lifetimes for one agent-remote process.
type Hub struct {
	dir string

	mu      sync.Mutex
	servers map[string]*server
}

// NewHub creates an idle hub; sockets are created lazily on first Offer.
func NewHub() *Hub {
	return &Hub{servers: map[string]*server{}}
}

// TryDial connects to a live master for h. It pings the master with a
// session probe so a dead socket never reaches Exec (which must not retry).
// Returns nil when no master is available.
func (hb *Hub) TryDial(h domain.Host) usecase.RemoteClient {
	if hb == nil {
		return nil
	}
	dir, err := defaultDir()
	if err != nil {
		return nil
	}
	path := socketPath(dir, h)
	if conn, derr := net.DialTimeout("unix", path, 500*time.Millisecond); derr != nil {
		// Nothing is listening: the file is stale debris from a killed
		// master. Remove it so the next Offer binds cleanly.
		os.Remove(path)
		return nil
	} else {
		conn.Close()
	}
	c := &muxClient{path: path}
	probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Test(probeCtx); err != nil {
		c.Close()
		return nil
	}
	return c
}

// Offer starts serving rc (a freshly dialed client) on the host socket.
// When another master already owns the socket it returns ErrMasterAlive
// and rc stays owned by the caller. On success rc is hub-owned: the hub
// closes it after the TTL, so the caller's Close is a no-op.
func (hb *Hub) Offer(h domain.Host, rc usecase.RemoteClient, banner string, ttl time.Duration) error {
	if hb == nil {
		return ErrMasterAlive
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	dir, err := defaultDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := socketPath(dir, h)
	ln, err := net.Listen("unix", path)
	if err != nil {
		if masterAlive(path) {
			return ErrMasterAlive
		}
		// Stale socket from a killed process: recover.
		os.Remove(path)
		ln, err = net.Listen("unix", path)
		if err != nil {
			return err
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	s := &server{rc: rc, banner: banner, ttl: ttl, ln: ln, done: make(chan struct{})}
	hb.mu.Lock()
	hb.servers[path] = s
	hb.mu.Unlock()
	go func() {
		s.serve()
		hb.mu.Lock()
		delete(hb.servers, path)
		hb.mu.Unlock()
	}()
	return nil
}

// Wait blocks until every hub-owned master has exited (TTL expiry or
// failure). With no masters it returns immediately.
func (hb *Hub) Wait() {
	if hb == nil {
		return
	}
	hb.mu.Lock()
	servers := make([]*server, 0, len(hb.servers))
	for _, s := range hb.servers {
		servers = append(servers, s)
	}
	hb.mu.Unlock()
	for _, s := range servers {
		<-s.done
	}
}

// SpawnServe launches a detached child process (same binary) that dials the
// named host and serves its mux socket until the idle TTL. The child runs
// in its own session with stdio detached, so the caller can exit without
// waiting — the Go equivalent of OpenSSH's background ControlPersist fork.
func SpawnServe(hostName string, ttl time.Duration) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		envServe+"=1",
		envHost+"="+hostName,
		envTTL+"="+ttl.String(),
	)
	cmd.SysProcAttr = detached()
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	return cmd.Start()
}

// ServeEnv reports whether this process was started as a mux serve child.
func ServeEnv() bool { return os.Getenv(envServe) == "1" }

// ServeHost returns the host name passed to a serve child.
func ServeHost() string { return os.Getenv(envHost) }

// ServeTTL returns the TTL passed to a serve child (0 when unset).
func ServeTTL() time.Duration {
	d, _ := time.ParseDuration(os.Getenv(envTTL))
	return d
}

func masterAlive(path string) bool {
	conn, err := net.DialTimeout("unix", path, 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// server holds one master connection and serves mux requests until the
// TTL expires with no activity (or the underlying client fails hard).
type server struct {
	rc     usecase.RemoteClient
	banner string
	ttl    time.Duration
	ln     net.Listener

	lastUse  atomic.Int64
	active   atomic.Int32
	doneOnce sync.Once
	done     chan struct{}
}

func (s *server) serve() {
	defer func() {
		s.ln.Close()
		s.rc.Close()
		os.Remove(s.ln.Addr().String())
		close(s.done)
	}()
	s.lastUse.Store(time.Now().UnixNano())
	stopIdle := make(chan struct{})
	defer close(stopIdle)
	go s.watchIdle(stopIdle)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

// watchIdle closes the listener once the master has been idle past the TTL,
// which unblocks Accept and tears the server down.
func (s *server) watchIdle(stop <-chan struct{}) {
	interval := s.ttl / 4
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if s.active.Load() > 0 {
				continue
			}
			if time.Since(time.Unix(0, s.lastUse.Load())) > s.ttl {
				s.ln.Close()
				return
			}
		}
	}
}

func (s *server) handle(conn net.Conn) {
	defer conn.Close()
	s.active.Add(1)
	defer s.active.Add(-1)
	s.lastUse.Store(time.Now().UnixNano())

	var req request
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReaderSize(conn, 4<<20).ReadString('\n')
	if err != nil {
		return
	}
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		return
	}
	s.lastUse.Store(time.Now().UnixNano())
	conn.SetReadDeadline(time.Time{})

	var resp response
	resp.Banner = s.banner
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = usecase.DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if req.Command == "" {
		res, err := s.rc.Test(ctx)
		if err != nil {
			writeErr(conn, resp, err)
			s.hardFail(err)
			return
		}
		resp.ExitCode = 0
		_ = res // reachability proven by the probe; latency measured client-side
		writeResp(conn, resp)
		return
	}

	res, err := s.rc.Exec(ctx, req.Command)
	resp.Stdout, resp.Stderr, resp.ExitCode = res.Stdout, res.Stderr, res.ExitCode
	if err != nil {
		writeErr(conn, resp, err)
		s.hardFail(err)
		return
	}
	writeResp(conn, resp)
}

// hardFail tears the master down when the upstream client looks broken at
// the connection level (dead SSH conn, network loss): without this, the
// socket outlives a useless master and every subsequent exec pays the
// probe delay. Auth or plain remote-exit failures do not tear down.
func (s *server) hardFail(err error) {
	switch domain.CodeOf(err) {
	case domain.CodeConnectionFailed, domain.CodeTimeout, domain.CodeInternal:
		s.ln.Close()
	}
}

func writeErr(conn net.Conn, resp response, err error) {
	resp.ErrorCode = string(domain.CodeOf(err))
	resp.ErrorMsg = err.Error()
	writeResp(conn, resp)
}

func writeResp(conn net.Conn, resp response) {
	b, err := json.Marshal(resp)
	if err != nil {
		b = []byte(`{"error_code":"internal","error_msg":"cannot encode response"}`)
	}
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	conn.Write(append(b, '\n'))
}

// muxClient is the client side: one unix connection per command.
type muxClient struct {
	path string
}

func (c *muxClient) round(ctx context.Context, req request) (response, error) {
	conn, err := net.DialTimeout("unix", c.path, 2*time.Second)
	if err != nil {
		return response{}, &MuxError{Sent: false, Err: fmt.Errorf("mux dial: %s", err.Error())}
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	conn.SetDeadline(deadline)
	b, err := json.Marshal(req)
	if err != nil {
		return response{}, domain.Fail(domain.CodeInternal, "mux encode: "+err.Error())
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return response{}, &MuxError{Sent: false, Err: fmt.Errorf("mux write: %s", err.Error())}
	}
	line, err := bufio.NewReaderSize(conn, 4<<20).ReadString('\n')
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// The client-side deadline fired before the server's own
			// error response arrived: the command may still have run
			// remotely. Surface as timeout so augmentTimeout appends the
			// effective budget for the agent.
			return response{}, domain.Fail(domain.CodeTimeout,
				"mux response timed out; the command may still have run remotely")
		}
		return response{}, &MuxError{Sent: true, Err: fmt.Errorf("mux read: %s", err.Error())}
	}
	var resp response
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return response{}, &MuxError{Sent: true, Err: fmt.Errorf("mux decode: %s", err.Error())}
	}
	if resp.ErrorCode != "" {
		return resp, domain.Fail(domain.Code(resp.ErrorCode), resp.ErrorMsg)
	}
	return resp, nil
}

func (c *muxClient) Test(ctx context.Context) (domain.TestResult, error) {
	start := time.Now()
	resp, err := c.round(ctx, request{})
	if err != nil {
		return domain.TestResult{}, err
	}
	return domain.TestResult{Reachable: true, LatencyMs: time.Since(start).Milliseconds(), PreAuthBanner: resp.Banner}, nil
}

func (c *muxClient) Exec(ctx context.Context, cmd string) (domain.ExecResult, error) {
	timeoutMs := int64(0)
	if d, ok := ctx.Deadline(); ok {
		timeoutMs = time.Until(d).Milliseconds()
	}
	resp, err := c.round(ctx, request{Command: cmd, TimeoutMs: timeoutMs})
	if err != nil {
		return domain.ExecResult{PreAuthBanner: resp.Banner}, err
	}
	return domain.ExecResult{Stdout: resp.Stdout, Stderr: resp.Stderr, ExitCode: resp.ExitCode, PreAuthBanner: resp.Banner}, nil
}

// Close is a no-op for the client side: each round dials its own socket
// connection, and the master keeps the upstream SSH connection for later
// invocations.
func (c *muxClient) Close() error { return nil }

var _ usecase.RemoteClient = (*muxClient)(nil)
