package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/wangkang/fortify/files"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: lock_test_helper <shared/exclusive> <filename>")
		os.Exit(1)
	}

	lockType := os.Args[1]
	filename := os.Args[2]

	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println("Failed to open file:", err)
		os.Exit(1)
	}
	defer func(file *os.File) { _ = file.Close() }(file)

	fd := file.Fd()

	if lockType == "exclusive" {
		fmt.Println("Acquiring exclusive lock in separate process...")
		err = files.AcquireExclusiveLock(fd)
		if err != nil {
			fmt.Println("Failed to acquire exclusive lock:", err)
			os.Exit(1)
		}
	} else if lockType == "shared" {
		fmt.Println("Acquiring shared lock in separate process...")
		err = files.AcquireSharedLock(fd)
		if err != nil {
			fmt.Println("Failed to acquire shared lock:", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Unknown lock type:", lockType)
		os.Exit(1)
	}

	// Setup signal handling for SIGUSR1
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, os.Kill)

	// Wait for signal or sleep for 5 seconds
	select {
	case <-signalChannel:
		fmt.Println("Received signal. Releasing lock and exiting...")
	case <-time.After(5 * time.Second):
		fmt.Println("Timed out after 5 seconds. Releasing lock and exiting...")
	}

	if err = files.ReleaseLock(fd); err != nil {
		fmt.Println("Failed to release lock:", err)
		os.Exit(1)
	}
}
