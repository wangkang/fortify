package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/files"
	"github.com/struqt/fortify/fortifier"
)

func init() {
	var o string
	c := &cobra.Command{
		Short: "Decrypt the fortified input file",
		Use:   "decrypt -i <input-file> [flags] <key1> [key2] ...",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return decrypt(flagIn, o, args)
		},
	}
	c.SetUsageTemplate(fmt.Sprintf(`%s
Required Arguments:
Required Arguments:
  <key1>   Path to the first secret share file or private key file if cipher key kind of <input-file> is 'rsa'
  [key2]   [Required cipher key kind of <input-file> is 'sss'] Path to the second secret share file
  ...      Additional paths to secret share files (all files remain unmodified)
`, c.UsageTemplate()))
	root.AddCommand(c)
	initFlagHelp(c)
	initFlagTruncate(c)
	initFlagVerbose(c)
	initFlagIn(c, "[Required] Path of the fortified/encrypted input file")
	_ = c.MarkFlagRequired("in")
	c.Flags().StringVarP(&o, "out", "o", "output.data", "Path of the output decrypted file")
}

func decrypt(input, output string, args []string) (err error) {
	files.SetVerbose(flagVerbose)
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
	if flagVerbose {
		fmt.Printf("%s\n", layout.String())
	}
	meta := layout.Metadata()
	var f *fortifier.Fortifier
	if f, _, err = newFortifier(meta.Key, meta, args); err != nil {
		return
	}
	var dec fortifier.Decrypter
	if dec = fortifier.NewDecrypter(meta.Mode, f); dec == nil {
		err = fmt.Errorf("unknown cipher mode name: %s", meta.Mode)
		return
	}
	if out, oCloseFn, err = files.OpenOutputFile(output, flagTruncate); err != nil {
		return
	}
	defer oCloseFn()
	return dec.DecryptFile(in, out, layout)
}
