package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/files"
	"github.com/struqt/fortify/fortifier"
)

func init() {
	var i, o, k, m string
	var T bool
	sub := &cobra.Command{Use: "encrypt", Short: "Encrypt any file (includes executable file)"}
	sub.Flags().StringVarP(&i, "in", "i", "", "path of the input file")
	sub.Flags().StringVarP(&o, "out", "o", "fortified.data", "path of the output encrypted file")
	sub.Flags().BoolVarP(&T, "truncate", "T", false, "truncate the output file before write")
	sub.Flags().StringVarP(&k, "key", "k", fortifier.CipherKeyKindSSS.String(), "kind of cipher key")
	sub.Flags().StringVarP(&m, "mode", "m", fortifier.CipherModeAes256CTR.String(), "mode of cipher")
	_ = sub.MarkFlagRequired("in")
	sub.Args = cobra.MinimumNArgs(0)
	sub.RunE = func(_ *cobra.Command, args []string) error {
		return encrypt(i, o, k, m, T, args)
	}
	root.AddCommand(sub)
}

func encrypt(input, output, key, mode string, truncate bool, args []string) (err error) {
	var f *fortifier.Fortifier
	if f, err = newFortifier(fortifier.CipherKeyKind(key), nil, args); err != nil {
		return
	}
	var enc fortifier.Encrypter
	if enc = fortifier.NewEncrypter(fortifier.CipherModeName(mode), f); enc == nil {
		err = fmt.Errorf("unknown cipher mode name: %s", mode)
		return
	}
	var in, out *os.File
	var iCloseFn, oCloseFn func()
	if in, iCloseFn, err = files.OpenInputFile(input); err != nil {
		return
	}
	defer iCloseFn()
	if out, oCloseFn, err = files.OpenOutputFile(output, truncate); err != nil {
		return
	}
	defer oCloseFn()
	return enc.EncryptFile(in, out)
}
