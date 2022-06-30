package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

func Execute(gitCommit string, builtTime string) {
	setGsandboxVersion(gitCommit, builtTime)

	var command = newGsandboxCommand()
	if err := command.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func setGsandboxVersion(gitCommit string, builtTime string) {
	var version = gsandbox.GetVersion()
	version.GitCommit = gitCommit

	if builtTime, err := strconv.ParseInt(builtTime, 10, 64); err == nil {
		version.BuiltTime = builtTime
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
