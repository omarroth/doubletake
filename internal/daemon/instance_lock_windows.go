package daemon

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func tryLockInstance(file *os.File) (busy bool, err error) {
	err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION), err
}
