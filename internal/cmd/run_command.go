package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

func newRunCommand() *cobra.Command {
	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var executor = &gsandbox.Executor{Prog: args[0], Args: args[1:]}
			executor.Run()
			fmt.Print(executor.Result.Info())
		},
	}

	runCommand.DisableFlagsInUseLine = true

	return runCommand
}
