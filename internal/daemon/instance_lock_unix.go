//go:build !windows

package daemon

import (
	"errors"
	"os"
	"syscall"
)

func tryLockInstance(file *os.File) (busy bool, err error) {
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN), err
}
