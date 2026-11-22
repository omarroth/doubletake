package main

import (
	"os"

	"doubletake/internal/daemon/daemoncli"
)

func main() {
	os.Exit(daemoncli.Run("doubletake-ctl", os.Args[1:]))
}
