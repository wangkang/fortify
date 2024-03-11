package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wangkang/fortify/files"
	"github.com/wangkang/fortify/fortifier"
)

var flagEncOut, flagEncKey, flagEncMode string

func init() {
	c := &cobra.Command{
		Short: "Encrypt an input file",
		Use:   "encrypt -i <input-file> [flags] <key1> [key2] ...",
		RunE: func(_ *cobra.Command, args []string) error {
			return encrypt(flagIn, flagEncOut, flagEncKey, flagEncMode, args)
		},
	}
	c.SetUsageTemplate(fmt.Sprintf(`%s
Required Arguments:
  <key1>   Path to the first secret share file or public key file if -k/--k is 'rsa'
  [key2]   [Required if -k/--k is 'sss'] Path to the second secret share file
  ...      Additional paths to secret share files (all files remain unmodified)
`, c.UsageTemplate()))
	root.AddCommand(c)
	initFlagHelp(c)
	initFlagTruncate(c)
	initFlagVerbose(c)
	initFlagIn(c, "[Required] Path of the input file")
	_ = c.MarkFlagRequired("in")
	c.Flags().StringVarP(&flagEncOut, "out", "o", "fortified.data",
		"Path of the output fortified/encrypted file")
	c.Flags().StringVarP(&flagEncKey, "key", "k", fortifier.CipherKeyKindSSS.String(),
		"Cipher key kind name, options: [sss|rsa]")
	c.Flags().StringVarP(&flagEncMode, "mode", "m", fortifier.CipherModeAes256CTR.String(),
		"Cipher mode name, options: [aes256-ctr|aes256-ofb|aes256-cfb]")
}

func encrypt(input, output, key, mode string, args []string) (err error) {
	files.SetVerbose(flagVerbose)
	var f *fortifier.Fortifier
	if f, _, err = newFortifier(fortifier.CipherKeyKind(key), nil, args); err != nil {
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
	if out, oCloseFn, err = files.OpenOutputFile(output, flagTruncate); err != nil {
		return
	}
	defer oCloseFn()
	return enc.EncryptFile(in, out)
}
