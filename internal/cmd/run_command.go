package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox/internal/gsandbox"
)

func newRunCommand() *cobra.Command {
	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var result = gsandbox.Run(args[0], args[1:])
			fmt.Print(result.Info())
		},
	}

	runCommand.DisableFlagsInUseLine = true

	return runCommand
}
