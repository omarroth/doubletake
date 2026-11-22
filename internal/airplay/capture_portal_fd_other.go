//go:build cgo && (darwin || windows)

package airplay

import (
	"errors"
	"os"
)

func linkedPortalArguments([]string, *os.File) ([]string, func(), error) {
	return nil, nil, errors.New("PipeWire portal capture requires Linux")
}
