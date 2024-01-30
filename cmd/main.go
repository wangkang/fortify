package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var root = &cobra.Command{Use: "fortify"}

func Run() int {
	if err := root.Execute(); err == nil {
		return 0
	} else {
		fmt.Println(err)
		return 1
	}
}
