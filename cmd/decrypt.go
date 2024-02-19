package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/files"
	"github.com/struqt/fortify/fortifier"
)

func init() {
	var i, o string
	var T bool
	sub := &cobra.Command{Use: "decrypt", Short: "Decrypt the fortified file"}
	sub.Flags().StringVarP(&i, "in", "i", "", "path of the fortified input file")
	sub.Flags().StringVarP(&o, "out", "o", "/dev/null", "path of the output decrypted file")
	sub.Flags().BoolVarP(&T, "truncate", "T", false, "truncate the output file before write")
	_ = sub.MarkFlagRequired("in")
	sub.Args = cobra.MinimumNArgs(1)
	sub.RunE = func(_ *cobra.Command, args []string) error {
		return decrypt(i, o, T, args)
	}
	root.AddCommand(sub)
}

func decrypt(input, output string, truncate bool, args []string) (err error) {
	var in, out *os.File
	var iCloseFn, oCloseFn func()
	if in, iCloseFn, err = files.OpenInputFile(input); err != nil {
		return
	}
	defer iCloseFn()
	layout := &fortifier.FileLayout{}
	if err = layout.ReadHeadIn(in); err != nil {
		return
	}
	fmt.Printf("%s\n", layout)
	meta := layout.Metadata()
	var f *fortifier.Fortifier
	if f, err = newFortifier(meta.Key, meta, args); err != nil {
		return
	}
	var dec fortifier.Decrypter
	if dec = fortifier.NewDecrypter(meta.Mode, f); dec == nil {
		err = fmt.Errorf("unknown cipher mode name: %s", meta.Mode)
		return
	}
	if out, oCloseFn, err = files.OpenOutputFile(output, truncate); err != nil {
		return
	}
	defer oCloseFn()
	return dec.DecryptFile(in, out, layout)
}
