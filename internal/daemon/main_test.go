package daemon

import (
	"fmt"
	"os"
	"testing"

	"doubletake/internal/airplay"
)

func TestMain(m *testing.M) {
	if handled, err := airplay.RunAudioOutputGuard(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	os.Exit(m.Run())
}
