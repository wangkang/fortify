//go:build unix && !windows

package files

import "syscall"

func ReleaseLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_UN)
}

func AcquireExclusiveLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
}

func AcquireSharedLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_SH|syscall.LOCK_NB)
}
