package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"agent-remote/internal/domain"
)

// keyPrefix marks every ephemeral key pushed by agent-remote so the
// cleanup command can find and purge orphaned entries.
const keyPrefix = "agent-remote-ephemeral-"

// ephemeralKey holds a generated keypair formatted for SSH use.
type ephemeralKey struct {
	Public  string // authorized_keys line (one-liner with comment)
	Private string // PEM-encoded private key for ssh -i
	ID      string // unique session marker
}

// generateEphemeralKey creates a one-time RSA keypair formatted for
// authorized_keys and ssh -i. The key never touches the local disk.
func generateEphemeralKey() (*ephemeralKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, domain.Fail(domain.CodeInternal, "key generation: "+err.Error())
	}
	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, domain.Fail(domain.CodeInternal, "public key marshal: "+err.Error())
	}
	id := fmt.Sprintf("%x", priv.PublicKey.N.BitLen()) + fmt.Sprintf("%p", priv)
	comment := keyPrefix + id
	pubKey := string(ssh.MarshalAuthorizedKey(sshPub))
	// Strip the trailing newline and append our comment marker.
	pubKey = strings.TrimRight(pubKey, "\n") + " " + comment + "\n"
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	return &ephemeralKey{
		Public:  pubKey,
		Private: string(privPEM),
		ID:      id,
	}, nil
}

// DirectSyncConfig holds the resolved parameters for a direct sync session.
type DirectSyncConfig struct {
	SrcHost string
	SrcPath string
	DstHost string
	DstPath string
	DstAddr string // user@dst-address for scp
	Delete  bool
}

// DirectSync sets up an ephemeral SSH key, pushes a watch-and-copy pipeline
// to the source server, and blocks until ctx is cancelled. On exit (or
// signal), it cleans up the key from both servers. The returned function
// must be called for guaranteed cleanup (use with defer or signal handler).
func DirectSync(ctx context.Context, store HostStore, secrets SecretResolver, factory NewClienter, cfg DirectSyncConfig) (func(), error) {
	fmt.Fprintf(os.Stderr, "[direct-sync] generating keypair\n")
	key, err := generateEphemeralKey()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "[direct-sync] keypair generated\n")
	privPath := "/tmp/" + keyPrefix + key.ID

	cleanup := func() {
		removeCmd := fmt.Sprintf("rm -f %s", privPath)
		_, _, _ = Exec(context.Background(), store, secrets, factory, cfg.SrcHost, ExecOptions{Command: removeCmd})
		cleanAuthorized := fmt.Sprintf(`sed -i '/%s/d' ~/.ssh/authorized_keys`, keyPrefix+key.ID)
		_, _, _ = Exec(context.Background(), store, secrets, factory, cfg.DstHost, ExecOptions{Command: cleanAuthorized})
	}

	// Push pubkey to destination.
	fmt.Fprintf(os.Stderr, "[direct-sync] pushing pubkey to %s\n", cfg.DstHost)
	pushPub := fmt.Sprintf(`mkdir -p ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`, strings.TrimSpace(key.Public))
	_, _, err = Exec(ctx, store, secrets, factory, cfg.DstHost, ExecOptions{Command: pushPub})
	if err != nil {
		cleanup()
		return nil, domain.Fail(domain.CodeConnectionFailed, "push pubkey to "+cfg.DstHost+": "+err.Error())
	}

	// Push privkey to source.
	fmt.Fprintf(os.Stderr, "[direct-sync] pushing privkey to %s\n", cfg.SrcHost)
	pushPriv := fmt.Sprintf(`echo '%s' > %s && chmod 600 %s`, key.Private, privPath, privPath)
	_, _, err = Exec(ctx, store, secrets, factory, cfg.SrcHost, ExecOptions{Command: pushPriv})
	if err != nil {
		cleanup()
		return nil, domain.Fail(domain.CodeConnectionFailed, "push privkey to "+cfg.SrcHost+": "+err.Error())
	}
	fmt.Fprintf(os.Stderr, "[direct-sync] privkey pushed, verifying...\n")
	_, verifyRes, err := Exec(ctx, store, secrets, factory, cfg.SrcHost,
		ExecOptions{Command: fmt.Sprintf("ls -la %s", privPath)})
	fmt.Fprintf(os.Stderr, "[direct-sync] verify: err=%v exit=%d stdout=%q stderr=%q\n", err, verifyRes.ExitCode, verifyRes.Stdout, verifyRes.Stderr)

	// Build and run the watch pipeline on the source.
	fmt.Fprintf(os.Stderr, "[direct-sync] starting watch on %s\n", cfg.SrcHost)
	watchCmd := buildWatchScript(cfg, privPath)
	_, _, execErr := Exec(ctx, store, secrets, factory, cfg.SrcHost,
		ExecOptions{Command: watchCmd, Timeout: directSyncMaxTimeout})
	cleanup()
	if execErr != nil && ctx.Err() == nil {
		return cleanup, domain.Fail(domain.CodeConnectionFailed, "direct sync: "+execErr.Error())
	}
	return cleanup, nil
}

// directSyncMaxTimeout bounds the watch pipeline. In practice the session
// ends via ctx cancellation (Ctrl+C), not this timeout.
const directSyncMaxTimeout = 8760 * time.Hour

// buildWatchScript constructs the shell pipeline that runs on the source
// server. Uses a polling loop with `find -newer` as the change detector —
// no inotifywait or external package required. Every SSH/scp invocation
// reuses the ephemeral key pushed at session start.
func buildWatchScript(cfg DirectSyncConfig, privPath string) string {
	// Write the watch script to a temp file, then execute it. This avoids
	// shell escaping issues from inline bash -c. SIGHUP trap kills the loop
	// when the SSH session drops (prevents orphan processes).
	srcPath := strings.TrimRight(cfg.SrcPath, "/")
	dstPath := strings.TrimRight(cfg.DstPath, "/")
	script := fmt.Sprintf(`trap 'rm -f %s %s.watch.sh; exit 0' HUP INT TERM
MARKER="%s.marker"
touch "$MARKER"
# Initial sync: copy all existing files before watching for changes.
find "%s" -type f 2>/dev/null | while IFS= read -r file; do
  relative="${file#%s/}"
  dir=$(dirname "%s/$relative")
  ssh -i %s -o StrictHostKeyChecking=no %s "mkdir -p '$dir'" < /dev/null
  scp -i %s -o StrictHostKeyChecking=no "$file" "%s:%s/$relative" < /dev/null
done
while sleep 2; do
  CHANGED=$(find "%s" -newer "$MARKER" -type f 2>/dev/null)
  if [ -n "$CHANGED" ]; then
    echo "$CHANGED" | while IFS= read -r file; do
      relative="${file#%s/}"
      dir=$(dirname "%s/$relative")
      ssh -i %s -o StrictHostKeyChecking=no %s "mkdir -p '$dir'" < /dev/null
      scp -i %s -o StrictHostKeyChecking=no "$file" "%s:%s/$relative" < /dev/null
    done
    touch "$MARKER"
  fi
done`,
		privPath, privPath, privPath,
		srcPath, srcPath, dstPath, privPath, cfg.DstAddr, privPath, cfg.DstAddr, dstPath,
		srcPath, srcPath, dstPath, privPath, cfg.DstAddr, privPath, cfg.DstAddr, dstPath)
	scriptPath := privPath + ".watch.sh"
	// Write script to source, then execute it. Exec blocks until ctx cancels.
	writeScript := fmt.Sprintf(`cat > %s <<'WATCHER_EOF'
%s
WATCHER_EOF
chmod +x %s
bash %s`, scriptPath, script, scriptPath, scriptPath)
	return writeScript
}
