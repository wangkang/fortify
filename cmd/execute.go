package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/files"
	"github.com/struqt/fortify/fortifier"
)

func init() {
	sub := &cobra.Command{Use: "execute", Short: "Decrypt the fortified file"}
	var i string
	sub.Flags().StringVarP(&i, "in", "i", "", "path of the fortified input file")
	_ = sub.MarkFlagRequired("in")
	sub.Args = cobra.MinimumNArgs(1)
	sub.RunE = func(_ *cobra.Command, args []string) error { return execute(i, args) }
	root.AddCommand(sub)
}

func execute(input string, args []string) (err error) {
	defer func() { fmt.Println("Executed") }()
	var in *os.File
	var iCloseFn func()
	if in, iCloseFn, err = files.OpenInputFile(input); err != nil {
		return
	}
	defer iCloseFn()
	layout := &fortifier.FileLayout{}
	if err = layout.ReadHeadIn(in); err != nil {
		return
	}
	//fmt.Printf("%s\n", layout)
	meta := layout.Metadata()
	var f *fortifier.Fortifier
	if f, err = files.NewFortifier(meta.Key, args); err != nil {
		return
	}
	var dec fortifier.Decrypter
	if dec = fortifier.NewDecrypter(meta.Mode, f); dec == nil {
		err = fmt.Errorf("unknown cipher mode name: %s", meta.Mode)
		return
	}
	var out *os.File
	out, err = os.CreateTemp("", ".bin")
	defer func() {
		_ = out.Close()
		_ = os.Remove(out.Name())
		//fmt.Printf("%s removed\n", out.Name())
	}()
	//started := time.Now()
	//fmt.Printf("%s *-->O %s %d bytes [%s %s]\n", in.Name(), out.Name(), layout.DataLen(), meta.Key, meta.Mode)
	r := bufio.NewReaderSize(in, 128*1024)
	if err = dec.Decrypt(r, out, layout); err != nil {
		return
	}
	//fmt.Printf("%s *-->O %s %d bytes (%v) OK\n", in.Name(), out.Name(), layout.DataLen(), time.Since(started))
	var wg sync.WaitGroup
	var process *os.Process
	chanSignal := make(chan os.Signal, 1)
	signal.Notify(chanSignal, os.Interrupt, syscall.SIGTERM)
	if process, err = start(out, &wg, chanSignal); err != nil {
		fmt.Printf("failed to run program: %v\n", err)
		return nil
	}
	sig := <-chanSignal
	_ = process.Signal(sig)
	wg.Wait()
	return
}

func permit(path string) error {
	cmd := exec.Command("/bin/sh", "-c", "chmod u+x "+path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chmod failed: %v", err)
	}
	return nil
}

func start(out *os.File, wg *sync.WaitGroup, chanSignal chan os.Signal) (*os.Process, error) {
	if err := permit(out.Name()); err != nil {
		fmt.Printf("failed to add permission: %v\n", err)
		return nil, err
	}
	path := out.Name()
	cmd := exec.Command(path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return cmd.Process, fmt.Errorf("failed to start program: %v", err)
	}
	//fmt.Printf("%s started\n", path)
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		if err := cmd.Wait(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "program execution failed: %v\n", err)
		}
		wg.Done()
		chanSignal <- syscall.SIGTERM
	}(wg)
	return cmd.Process, nil
}
