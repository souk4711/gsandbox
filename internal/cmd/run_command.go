package cmd

import (
	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

func newRunCommand() *cobra.Command {
	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var executor = &gsandbox.Executor{
				Prog: args[0],
				Args: args[1:],
			}
			return executor.Start()
		},
	}

	runCommand.DisableFlagsInUseLine = true

	return runCommand
}
