package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var verbose bool
var verboseSetOnce sync.Once

func SetVerbose(b bool) {
	verboseSetOnce.Do(func() {
		verbose = b
	})
}

func Stat(file string) (stat os.FileInfo, path string, err error) {
	if path, err = filepath.Abs(strings.TrimSpace(file)); err != nil {
		return
	}
	if stat, err = os.Stat(path); err != nil {
		return
	}
	if stat.IsDir() {
		return nil, path, fmt.Errorf("%s is a directory, not a file", path)
	}
	return
}

func OpenInputFile(name string) (file *os.File, closeFn func(), err error) {
	if file, err = openForRead(name); err != nil {
		return
	}
	if verbose {
		fmt.Printf("%s --> open\n", file.Name())
	}
	closeFn = func() {
		_ = ReleaseLock(file.Fd())
		_ = file.Close()
		if verbose {
			fmt.Printf("%s --> close\n", file.Name())
		}
	}
	return
}

func OpenOutputFile(name string, truncate bool, flags ...int) (file *os.File, closeFn func(), err error) {
	if file, err = openForWrite(name, truncate, 0600, flags...); err != nil {
		return
	}
	if verbose {
		fmt.Printf("%s <-- open\n", file.Name())
	}
	closeFn = func() {
		_ = file.Sync()
		_ = ReleaseLock(file.Fd())
		_ = file.Close()
		if verbose {
			fmt.Printf("%s <-- close\n", file.Name())
		}
	}
	return
}

func openForRead(name string) (*os.File, error) {
	var (
		err  error
		path string
		file *os.File
		stat os.FileInfo
	)
	if stat, path, err = Stat(name); err != nil {
		return nil, err
	}
	if stat.Size() == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	if file, err = os.OpenFile(path, os.O_RDONLY, 0400); err != nil {
		return nil, err
	} else {
		if err = AcquireSharedLock(file.Fd()); err != nil {
			_ = file.Close()
			return nil, err
		}
		return file, nil
	}
}

func openForWrite(name string, truncate bool, mode os.FileMode, flags ...int) (*os.File, error) {
	var (
		err  error
		path string
		file *os.File
		stat os.FileInfo
	)
	if path, err = filepath.Abs(strings.TrimSpace(name)); err != nil {
		return nil, err
	}
	flag := os.O_WRONLY | os.O_CREATE
	for _, f := range flags {
		flag |= f
	}
	if truncate {
		flag |= os.O_TRUNC
	}
	if file, err = os.OpenFile(path, flag, mode); err != nil {
		return nil, err
	}
	if stat, path, err = Stat(name); err != nil {
		return nil, err
	}
	if stat.Size() > 0 {
		return nil, fmt.Errorf("%s is not empty", path)
	}
	if err = AcquireExclusiveLock(file.Fd()); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
