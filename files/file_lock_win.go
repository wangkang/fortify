//go:build windows && !unix

package files

import "golang.org/x/sys/windows"

func ReleaseLock(fd uintptr) error {
	return windows.UnlockFileEx(windows.Handle(fd), 0, 1, 0, windowsOverlapped())
}

func AcquireExclusiveLock(fd uintptr) error {
	var flags uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY | windows.LOCKFILE_EXCLUSIVE_LOCK
	return windows.LockFileEx(windows.Handle(fd), flags, 0, 1, 0, windowsOverlapped())
}

func AcquireSharedLock(fd uintptr) error {
	var flags uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY
	return windows.LockFileEx(windows.Handle(fd), flags, 0, 1, 0, windowsOverlapped())
}

func windowsOverlapped() *windows.Overlapped {
	var m1 uint32 = (1 << 32) - 1
	return &windows.Overlapped{Offset: m1, OffsetHigh: m1}
}
