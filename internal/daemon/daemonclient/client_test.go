package daemonclient

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"doubletake/internal/daemon"
)

func TestClientResetRestoreTokenSendsTargetedCommand(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "doubletake.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	requestCh := make(chan daemon.Request, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var request daemon.Request
		if json.NewDecoder(conn).Decode(&request) != nil {
			return
		}
		requestCh <- request
		_ = json.NewEncoder(conn).Encode(daemon.Response{OK: true, State: daemon.StateConnecting})
	}()
	client := New(socketPath)

	response, err := client.ResetRestoreToken("192.0.2.10")

	if err != nil {
		t.Fatalf("ResetRestoreToken: %v", err)
	}
	if response == nil || !response.OK {
		t.Fatalf("response = %+v", response)
	}
	select {
	case request := <-requestCh:
		if request.Cmd != "reset-restore-token" || request.Target != "192.0.2.10" {
			t.Fatalf("request = %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("client did not send reset request")
	}
}
