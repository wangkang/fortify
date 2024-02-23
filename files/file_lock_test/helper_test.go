package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/struqt/fortify/files"
)

func TestExclusiveLock(t *testing.T) {
	file, err := os.CreateTemp("", "test_exclusive_lock.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func(file *os.File) { _ = os.Remove(file.Name()) }(file)
	defer func(file *os.File) { _ = file.Close() }(file)
	defer func(file *os.File) { _ = files.ReleaseLock(file.Fd()) }(file)
	fd := file.Fd()
	var wg sync.WaitGroup
	wg.Add(1)
	cmd := exec.Command("go", "run", "helper.go", "exclusive", file.Name())
	if err = cmd.Start(); err != nil {
		fmt.Printf("Failed to start process: %v\n", err)
	}
	go func(file *os.File, cmd *exec.Cmd) {
		if err = cmd.Wait(); err != nil {
			fmt.Printf("--- INFO: Failed to run process: %v\n", err)
		}
		wg.Done()
	}(file, cmd)
	time.Sleep(800 * time.Millisecond)
	if err = files.AcquireSharedLock(fd); err == nil {
		t.Fatal("Expected failure to acquire shared lock in the current process, but succeeded")
	} else {
		fmt.Printf("--- INFO: Failed to acquire shared lock: %v\n", err)
	}
	if err = files.AcquireExclusiveLock(fd); err == nil {
		t.Fatal("Expected failure to acquire exclusive lock in the current process, but succeeded")
	} else {
		fmt.Printf("--- INFO: Failed to acquire exclusive lock: %v\n", err)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	wg.Wait()
}

func TestSharedLock(t *testing.T) {
	file, err := os.CreateTemp("", "test_shared_lock.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func(file *os.File) { _ = os.Remove(file.Name()) }(file)
	defer func(file *os.File) { _ = file.Close() }(file)
	defer func(file *os.File) { _ = files.ReleaseLock(file.Fd()) }(file)
	fd := file.Fd()
	var wg sync.WaitGroup
	wg.Add(1)
	cmd := exec.Command("go", "run", "helper.go", "shared", file.Name())
	if err = cmd.Start(); err != nil {
		fmt.Printf("Failed to start process: %v\n", err)
	}
	go func(file *os.File, cmd *exec.Cmd) {
		if err = cmd.Wait(); err != nil {
			fmt.Printf("--- INFO: Failed to run process: %v\n", err)
		}
		wg.Done()
	}(file, cmd)
	time.Sleep(800 * time.Millisecond)
	if err = files.AcquireSharedLock(fd); err != nil {
		fmt.Printf("--- INFO: Failed to acquire shared lock: %v\n", err)
		t.Fatal("Expected success to acquire shared lock in the current process, but failed")
	}
	if err = files.AcquireExclusiveLock(fd); err == nil {
		t.Fatal("Expected failure to acquire exclusive lock in the current process, but succeeded")
	} else {
		fmt.Printf("--- INFO: Failed to acquire exclusive lock: %v\n", err)
	}
	_ = cmd.Process.Signal(syscall.SIGKILL)
	wg.Wait()
}
