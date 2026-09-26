package usecase

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

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
	key, err := generateEphemeralKey()
	if err != nil {
		return nil, err
	}
	privPath := "/tmp/" + keyPrefix + key.ID

	cleanup := func() {
		removeCmd := fmt.Sprintf("rm -f %s", privPath)
		_, _, _ = Exec(context.Background(), store, secrets, factory, cfg.SrcHost, ExecOptions{Command: removeCmd})
		cleanAuthorized := fmt.Sprintf(`sed -i '/%s/d' ~/.ssh/authorized_keys`, keyPrefix+key.ID)
		_, _, _ = Exec(context.Background(), store, secrets, factory, cfg.DstHost, ExecOptions{Command: cleanAuthorized})
	}

	// Push pubkey to destination.
	pushPub := fmt.Sprintf(`mkdir -p ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`, strings.TrimSpace(key.Public))
	_, _, err = Exec(ctx, store, secrets, factory, cfg.DstHost, ExecOptions{Command: pushPub})
	if err != nil {
		cleanup()
		return nil, domain.Fail(domain.CodeConnectionFailed, "push pubkey to "+cfg.DstHost+": "+err.Error())
	}

	// Push privkey to source.
	pushPriv := fmt.Sprintf(`echo '%s' > %s && chmod 600 %s`, key.Private, privPath, privPath)
	_, _, err = Exec(ctx, store, secrets, factory, cfg.SrcHost, ExecOptions{Command: pushPriv})
	if err != nil {
		cleanup()
		return nil, domain.Fail(domain.CodeConnectionFailed, "push privkey to "+cfg.SrcHost+": "+err.Error())
	}

	// Build and run the watch pipeline on the source.
	watchCmd := buildWatchScript(cfg, privPath)
	_, _, execErr := Exec(ctx, store, secrets, factory, cfg.SrcHost, ExecOptions{Command: watchCmd})
	cleanup()
	if execErr != nil && ctx.Err() == nil {
		return cleanup, domain.Fail(domain.CodeConnectionFailed, "direct sync: "+execErr.Error())
	}
	return cleanup, nil
}

// buildWatchScript constructs the shell pipeline that runs on the source
// server: inotifywait streams events, a while-loop scps each changed file
// directly to the destination using the ephemeral key.
func buildWatchScript(cfg DirectSyncConfig, privPath string) string {
	deleteClause := ""
	if cfg.Delete {
		deleteClause = `
  if echo "$event" | grep -q DELETE; then
    ssh -i %s -o StrictHostKeyChecking=no %s "rm -f '%s/\${file#%s/}'"
    continue
  fi`
		deleteClause = fmt.Sprintf(deleteClause, privPath, cfg.DstAddr, cfg.DstPath, cfg.SrcPath)
	}
	return fmt.Sprintf(`inotifywait -m -r --format '%%w%%f %%e' -e close_write,create,moved_to,delete %s 2>/dev/null | while read file event; do%s
  relative="\${file#%s/}"
  dir="\$(dirname "%s/\$relative")"
  ssh -i %s -o StrictHostKeyChecking=no %s "mkdir -p '$dir'"
  scp -i %s -o StrictHostKeyChecking=no "\$file" "%s:%s/\$relative"
done`,
		cfg.SrcPath, deleteClause, cfg.SrcPath, cfg.DstPath, privPath, cfg.DstAddr, privPath, cfg.DstAddr, cfg.DstPath)
}
