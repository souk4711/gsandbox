package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

func newVersionCommand() *cobra.Command {
	var versionCommand = &cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Run: func(cmd *cobra.Command, args []string) {
			var version = gsandbox.GetVersion()
			fmt.Print(version.Info())
		},
	}

	return versionCommand
}
