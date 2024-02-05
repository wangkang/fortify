package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/struqt/fortify/sss"
)

const partsDefault = 5
const thresholdDefault = 3
const randomBytesDefault = 32
const partFilePrefixDefault = "sss"

func init() {
	s3 := &cobra.Command{Use: "sss", Short: "Shamir's secret sharing"}

	combine := &cobra.Command{Use: "combine", Short: "Combine secret share files to recover the secret"}
	combine.Flags().StringP("out", "o", "", "One output file that contains the recovered secret")
	combine.Flags().BoolP("truncate", "T", false, "Truncate the output file before write")
	combine.RunE = sssCombineRunE
	combine.Args = cobra.MinimumNArgs(2)

	random := &cobra.Command{Use: "random", Short: "Split a random byte array into secret shares"}
	random.Flags().Uint8P("parts", "p", partsDefault, "Count of secret shares to split into")
	random.Flags().Uint8P("threshold", "t", thresholdDefault, "Minimum secret share count for secret recovery")
	random.Flags().StringP("prefix", "", partFilePrefixDefault, "File path prefix of one secret share")
	random.Flags().Uint16P("bytes", "b", randomBytesDefault, "Length of random byte array")
	random.RunE = sssRandomRunE

	split := &cobra.Command{Use: "split", Short: "Split a file to several secret shares"}
	split.Flags().Uint8P("parts", "p", 5, "Total part count to split")
	split.Flags().Uint8P("threshold", "t", 3, "Minimum part count to recover the secret")
	split.Flags().StringP("prefix", "", partFilePrefixDefault, "File path prefix of one secret share")
	split.RunE = sssSplitRunE
	split.Args = cobra.ExactArgs(1)

	s3.AddCommand(random, split, combine)
	root.AddCommand(s3)
}

func sssCombineRunE(cmd *cobra.Command, args []string) (err error) {
	var fileOut string
	if fileOut, err = cmd.Flags().GetString("out"); err != nil {
		return
	}
	var truncate bool
	if truncate, err = cmd.Flags().GetBool("truncate"); err != nil {
		return
	}
	if len(args) == 0 {
		err = errors.New("no arguments")
		return
	}
	return sss.CombinePartFiles(args, fileOut, truncate)
}

func sssSplitRunE(c *cobra.Command, args []string) (err error) {
	defer sss.CloseAllFilesForWrite()
	file := strings.TrimSpace(args[0])
	if len(file) == 0 {
		err = errors.New("no file specified")
		return
	}
	parts, threshold := sssSplitArgs(c)
	prefix, _ := c.Flags().GetString("prefix")
	return sss.SplitIntoFiles(file, parts, threshold, prefix)
}

func sssRandomRunE(c *cobra.Command, _ []string) (err error) {
	defer sss.CloseAllFilesForWrite()
	var bs uint16
	bs, err = c.Flags().GetUint16("bytes")
	if bs <= 0 {
		err = fmt.Errorf("invalid value of flag (--bytes): %d", bs)
	}
	if err != nil {
		return
	}
	secret := make([]byte, bs)
	if _, err = rand.Reader.Read(secret); err != nil {
		return
	}
	parts, threshold := sssSplitArgs(c)
	var ps []sss.Part
	if ps, err = sss.Split(secret, parts, threshold); err != nil {
		return
	}
	prefix, _ := c.Flags().GetString("prefix")
	return sss.AppendParts(ps, 0, 1, prefix)
}

func sssSplitArgs(c *cobra.Command) (parts, threshold uint8) {
	var err error
	if parts, err = c.Flags().GetUint8("parts"); err != nil || parts <= 0 {
		parts = partsDefault
	}
	if threshold, err = c.Flags().GetUint8("threshold"); err != nil || threshold <= 0 {
		threshold = thresholdDefault
	}
	return
}
