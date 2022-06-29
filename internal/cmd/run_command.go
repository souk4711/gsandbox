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
		RunE: func(cmd *cobra.Command, args []string) error {
			if result, err := gsandbox.Run(args[0], args[1:]); err != nil {
				return err
			} else {
				fmt.Print(result.Info())
				return nil
			}
		},
	}

	runCommand.DisableFlagsInUseLine = true

	return runCommand
}
