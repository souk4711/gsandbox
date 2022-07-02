package cmd

import (
	"fmt"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/goccy/go-json"
	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

func newRunCommand() *cobra.Command {
	var verbose bool
	var policyFilePath string
	var reportFilePath string

	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sandbox = gsandbox.NewSandbox()

			// Flag: verbose
			if verbose {
				var logger logr.Logger = funcr.New(func(prefix, args string) {
					fmt.Println(prefix, args)
				}, funcr.Options{}).WithName("Gsandbox")
				sandbox.WithLogger(logger)
			}

			// Flag: policy-file
			if policyFilePath != "" {
				if err := sandbox.LoadPolicyFromFile(policyFilePath); err != nil {
					return err
				}
			}

			// run
			var executor = sandbox.Run(args[0], args[1:])

			// Flag: report-file
			var resultData, _ = json.Marshal(executor.Result)
			var _ = os.WriteFile(reportFilePath, resultData, 0644)
			return nil
		},
	}

	runCommand.DisableFlagsInUseLine = true
	runCommand.Flags().StringVar(&policyFilePath, "policy-file", "", "use the specified policy configuration file")
	runCommand.Flags().StringVar(&reportFilePath, "report-file", "", "generate a JSON-formatted report at the specified location")
	runCommand.Flags().BoolVar(&verbose, "verbose", false, "turn on verbose mode")

	return runCommand
}
