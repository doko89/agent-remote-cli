package domain

import (
	"errors"
	"testing"
)

func TestProtocolAndAuthValid(t *testing.T) {
	if !ProtocolSSH.Valid() || !ProtocolWinRM.Valid() || Protocol("telnet").Valid() {
		t.Fatal("protocol validation wrong")
	}
	for _, m := range []AuthMethod{AuthKeyring, AuthEnv, AuthStdin, AuthKeyFile, AuthNone} {
		if !m.Valid() {
			t.Fatalf("%q should be valid", m)
		}
	}
	if AuthMethod("flag").Valid() {
		t.Fatal("bogus auth should be invalid")
	}
}

func TestDefaultPort(t *testing.T) {
	if (Host{Protocol: ProtocolSSH}).DefaultPort() != 22 {
		t.Fatal("ssh default port")
	}
	if (Host{Protocol: ProtocolWinRM}).DefaultPort() != 5985 {
		t.Fatal("winrm default port")
	}
	if (Host{Protocol: ProtocolSSH, Port: 2222}).DefaultPort() != 2222 {
		t.Fatal("explicit port must win")
	}
}

func TestCodeOf(t *testing.T) {
	if CodeOf(nil) != CodeOK {
		t.Fatal("nil must map to ok")
	}
	if CodeOf(Fail(CodeTimeout, "t")) != CodeTimeout {
		t.Fatal("ToolError code must survive")
	}
	if CodeOf(errors.New("x")) != CodeInternal {
		t.Fatal("plain error must map to internal")
	}
}

func TestDefaultFilterEnabled(t *testing.T) {
	if !DefaultFilter().Enabled {
		t.Fatal("default filter must be enabled")
	}
}
