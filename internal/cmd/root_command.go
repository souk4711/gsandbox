package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute() {
	var command = newGsandboxCommand()
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newGsandboxCommand() *cobra.Command {
	var rootCommand = &cobra.Command{
		Use:   "gsandbox",
		Short: "A sandbox for Linux which can be used to run untrusted programs",
	}

	rootCommand.SilenceErrors = true
	rootCommand.CompletionOptions.DisableDefaultCmd = true
	rootCommand.AddCommand(newVersionCommand())
	rootCommand.AddCommand(newRunCommand())

	return rootCommand
}
