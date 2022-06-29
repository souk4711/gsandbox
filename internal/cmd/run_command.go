package cmd

import (
	"os"

	"github.com/goccy/go-json"
	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox/internal/gsandbox"
)

func newRunCommand() *cobra.Command {
	var reportFile string

	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := gsandbox.Run(args[0], args[1:])
			if err != nil {
				return err
			}

			resultData, err := json.Marshal(&result)
			if err != nil {
				return err
			}

			if err := os.WriteFile(reportFile, resultData, 0644); err != nil {
				return err
			}

			return nil
		},
	}

	runCommand.DisableFlagsInUseLine = true
	runCommand.Flags().StringVarP(&reportFile, "reportFile", "", "proc-metadata.json", "Generate a JSON-formatted report at the specified location")

	return runCommand
}
