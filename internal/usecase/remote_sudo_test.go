package usecase

import (
	"strings"
	"testing"

	"agent-remote/internal/domain"
)

func TestSudoWrap(t *testing.T) {
	got := sudoWrap(`echo 'hello'`, "s3cret")
	want := `echo 's3cret' | sudo -S -p '' bash -c 'echo '\''hello'\'''`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSudoExec(t *testing.T) {
	store := &memStore{hosts: map[string]domain.Host{}}
	if _, err := AddHost(store, sshInput("sudo-host")); err != nil {
		t.Fatal(err)
	}
	var gotCmd string
	factory := recordingFactory{onExec: func(cmd string) { gotCmd = cmd }}
	_, _, err := Exec(testCtx(), store, stubSecrets{pw: "s3cret"}, factory, "sudo-host",
		ExecOptions{Command: "systemctl restart nginx", Sudo: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotCmd, "sudo -S") || !strings.Contains(gotCmd, "systemctl restart nginx") {
		t.Fatalf("unexpected sudo command: %q", gotCmd)
	}
	if !strings.Contains(gotCmd, "s3cret") {
		t.Fatal("password not present in sudo command")
	}
}
