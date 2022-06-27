package cmd

import (
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	runCommand.DisableFlagsInUseLine = true

	return runCommand
}
