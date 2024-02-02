package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

func OpenForRead(name string) (*os.File, error) {
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
		return file, nil
	}
}

func OpenForWrite(name string, truncate bool, mode os.FileMode) (*os.File, error) {
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
	return file, nil
}
