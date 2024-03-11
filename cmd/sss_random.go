package cmd

import (
	"crypto/rand"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wangkang/fortify/files"
	"github.com/wangkang/fortify/sss"
)

func init() {
	c := &cobra.Command{
		RunE:  sssRandomRunE,
		Use:   "random",
		Short: "Split a randomly generated byte array into secret shares",
	}
	ssss.AddCommand(c)
	initFlagHelp(c)
	initFlagTruncate(c)
	initFlagVerbose(c)
	initFlagPartsAndThreshold(c)
	initFlagPrefix(c, "File path prefix for the generated secret shares")
	initFlagBytes(c, defaultRandomBytes, "Length of the randomly generated byte array")
}

func sssRandomRunE(_ *cobra.Command, _ []string) (err error) {
	defer sss.CloseAllFilesForWrite()
	files.SetVerbose(flagVerbose)
	var bs = uint16(flagBytes)
	if bs == 0 || int(bs) != flagBytes {
		return fmt.Errorf("value of flag (--bytes / -b) is out of range (0,65535]: %d", flagBytes)
	}
	secret := make([]byte, bs)
	if _, err = rand.Reader.Read(secret); err != nil {
		return
	}
	var ps []sss.Part
	if ps, err = sss.Split(secret, flagSssParts, flagSssThreshold); err != nil {
		return
	}
	return sss.AppendParts(ps, 0, 1, flagPrefix, flagTruncate)
}
