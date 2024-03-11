package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wangkang/fortify/files"
	"github.com/wangkang/fortify/sss"
)

var flagSssCombineOut string

func init() {
	c := &cobra.Command{
		RunE:  sssCombineRunE,
		Use:   "combine -o <output-file> [flags] <input-file1> <input-file2> ...",
		Short: "Combine secret shares to recover the original data",
		Args:  cobra.MinimumNArgs(2),
	}
	c.SetUsageTemplate(fmt.Sprintf(`%s
Required Arguments:
  <input-file1>      Path to the first secret share file
  <input-file2>      Path to the second secret share file
  ...                Additional paths to secret share files (at least two required; all files remain unmodified)
`, c.UsageTemplate()))
	initFlagHelp(c)
	initFlagTruncate(c)
	initFlagVerbose(c)
	c.Flags().StringVarP(&flagSssCombineOut, "out", "o", "",
		"[Required] Specify the output file for the recovered original data")
	ssss.AddCommand(c)
}

func sssCombineRunE(_ *cobra.Command, args []string) error {
	files.SetVerbose(flagVerbose)
	file := strings.TrimSpace(flagSssCombineOut)
	if len(file) == 0 {
		return errors.New("empty path of the output file")
	}
	return sss.CombinePartFiles(args, file, flagTruncate, flagVerbose)
}
