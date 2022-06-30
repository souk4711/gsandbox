package cmd

import (
	"os"

	"github.com/goccy/go-json"
	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

func newRunCommand() *cobra.Command {
	var policyFilePath string
	var reportFilePath string

	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sandbox = gsandbox.Sandbox{}
			if policyFilePath != "" {
				if err := sandbox.LoadPolicyFromFile(policyFilePath); err != nil {
					return err
				}
			}

			var executor = sandbox.Run(args[0], args[1:])
			var resultData, _ = json.Marshal(&executor.Result)
			var _ = os.WriteFile(reportFilePath, resultData, 0644)
			return nil
		},
	}

	runCommand.DisableFlagsInUseLine = true
	runCommand.Flags().StringVar(&policyFilePath, "policy-file", "", "use the specified policy configuration file")
	runCommand.Flags().StringVar(&reportFilePath, "report-file", "proc-metadata.json", "generate a JSON-formatted report at the specified location")

	return runCommand
}
