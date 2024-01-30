package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

const Version = "#CD_VERSION_TAG"

func init() {
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version of the command",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(Version)
		},
	})
}
