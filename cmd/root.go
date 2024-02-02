package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/files"
)

var root = &cobra.Command{Use: "fortify"}

func init() {
	root.Flags().StringP("out", "o", "fortified.data", "path of the output encrypted file")
	root.Flags().BoolP("truncate", "T", false, "truncate the output file before write")
	root.RunE = rootRunE
	root.Args = cobra.ExactArgs(1)
}

func rootRunE(cmd *cobra.Command, args []string) (err error) {
	var in, out *os.File
	var iCloseFn, oCloseFn func()
	if out, oCloseFn, err = rootOpenOutputFile(cmd); err != nil {
		return
	}
	defer oCloseFn()
	if in, iCloseFn, err = rootOpenInputFile(args[0]); err != nil {
		return
	}
	defer iCloseFn()
	w := files.NewFortifiedWriter(out, &files.FortifiedFileHead{
		Parts: 2, Threshold: 2,
	})
	return w.WriteFile(in)
}

func rootOpenInputFile(name string) (file *os.File, closeFn func(), err error) {
	if file, err = files.OpenForRead(name); err != nil {
		return
	}
	fmt.Printf("Open: %v\n", file.Name())
	closeFn = func() {
		_ = file.Close()
		fmt.Printf("Close: %v\n", file.Name())
	}
	return
}

func rootOpenOutputFile(cmd *cobra.Command) (file *os.File, closeFn func(), err error) {
	var name string
	if name, err = cmd.Flags().GetString("out"); err != nil {
		return
	}
	var truncate bool
	if truncate, err = cmd.Flags().GetBool("truncate"); err != nil {
		return
	}
	if file, err = files.OpenForWrite(name, truncate, 0640); err != nil {
		return
	}
	fmt.Printf("Open: %v\n", file.Name())
	closeFn = func() {
		_ = file.Sync()
		_ = file.Close()
		fmt.Printf("Close: %v\n", file.Name())
	}
	return
}
