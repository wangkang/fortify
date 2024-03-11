package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wangkang/fortify/files"
	"github.com/wangkang/fortify/sss"
)

func init() {
	c := &cobra.Command{
		RunE:  sssSplitRunE,
		Use:   "split [flags] [input-file]",
		Short: "Split content of a input file into secret shares",
		Args:  cobra.MaximumNArgs(1),
	}
	c.SetUsageTemplate(fmt.Sprintf(`%s
Arguments:
  [input-file]   [Required if no -i/--in] Path of the input file. Ignored if -i/--in is specified
`, c.UsageTemplate()))
	ssss.AddCommand(c)
	initFlagHelp(c)
	initFlagVerbose(c)
	initFlagTruncate(c)
	initFlagPartsAndThreshold(c)
	initFlagIn(c, "[Required if no [input-file]] Path of the input file")
	initFlagPrefix(c, "File path prefix for the generated secret shares")
}

func sssSplitRunE(_ *cobra.Command, args []string) error {
	defer sss.CloseAllFilesForWrite()
	files.SetVerbose(flagVerbose)
	file := strings.TrimSpace(flagIn)
	if len(file) == 0 && len(args) > 0 {
		file = strings.TrimSpace(args[0])
	}
	if len(file) == 0 {
		return errors.New("empty path of the input file")
	}
	return sss.SplitIntoFiles(file, flagSssParts, flagSssThreshold, flagPrefix, flagTruncate, flagVerbose)
}
