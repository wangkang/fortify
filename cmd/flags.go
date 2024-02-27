package cmd

import (
	"github.com/spf13/cobra"
)

const (
	defaultSssParts     = 5
	defaultSssThreshold = 3
	defaultRandomBytes  = 32
)

var (
	flagVerbose      bool
	flagTruncate     bool
	flagIn           string
	flagPrefix       string
	flagBytes        int
	flagSssParts     uint8 = defaultSssParts
	flagSssThreshold uint8 = defaultSssThreshold
)

func initFlagVerbose(c *cobra.Command) {
	c.Flags().BoolVarP(&flagVerbose, "verbose", "v", false,
		"Enable verbose mode to print more information to the terminal")
}

func initFlagTruncate(c *cobra.Command) {
	c.Flags().BoolVarP(&flagTruncate, "truncate", "T", false, "Truncate the output file(s) before write")
}

func initFlagHelp(c *cobra.Command) {
	c.Flags().BoolP("help", "h", false, "Show help message")
}

func initFlagPartsAndThreshold(c *cobra.Command) {
	c.Flags().Uint8VarP(&flagSssParts, "parts", "p",
		defaultSssParts, "Number of secret shares to generate")
	c.Flags().Uint8VarP(&flagSssThreshold, "threshold", "t",
		defaultSssThreshold, "Minimum number of shares required for secret recovery")
}

func initFlagIn(c *cobra.Command, usage string) {
	c.Flags().StringVarP(&flagIn, "in", "i", "", usage)
}

func initFlagPrefix(c *cobra.Command, usage string) {
	c.Flags().StringVarP(&flagPrefix, "prefix", "P", "", usage)
}

func initFlagBytes(c *cobra.Command, value int, usage string) {
	c.Flags().IntVarP(&flagBytes, "bytes", "b", value, usage)
}
