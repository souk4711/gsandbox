package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute(gitCommit string, builtTime int64) {
	var command = newGsandboxCommand(gitCommit, builtTime)
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newGsandboxCommand(gitCommit string, builtTime int64) *cobra.Command {
	var rootCommand = &cobra.Command{
		Use:   "gsandbox",
		Short: "A sandbox for Linux which can be used to run untrusted programs",
	}

	rootCommand.CompletionOptions.DisableDefaultCmd = true
	rootCommand.AddCommand(newVersionCommand(gitCommit, builtTime))

	return rootCommand
}
