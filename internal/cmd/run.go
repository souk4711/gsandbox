package cmd

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

var (
	//go:embed policies/*
	policiesFS embed.FS
)

func newRunCommand() *cobra.Command {
	var policyFilePath string
	var reportFilePath string
	var verbose bool
	var workDir string
	var policy string

	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sandbox = gsandbox.NewSandbox()

			// cleanup
			var c = make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt)
			go func() {
				<-c
				sandbox.Cleanup()
			}()

			// Flag: verbose
			if verbose {
				var logger logr.Logger = funcr.New(func(prefix, args string) {
					fmt.Println(prefix, args)
				}, funcr.Options{}).WithName("Gsandbox")
				sandbox.WithLogger(logger)
			}

			// Flag: policy-file
			if policyFilePath == "" {
				data, err := policiesFS.ReadFile(fmt.Sprintf("policies/%s.yml", policy))
				if err != nil {
					return err
				} else {
					if err := sandbox.LoadPolicyFromData(data); err != nil {
						return err
					}
				}
			} else {
				if err := sandbox.LoadPolicyFromFile(policyFilePath); err != nil {
					return err
				}
			}

			// Flag: work-dir
			var executor = sandbox.NewExecutor(args[0], args[1:])
			if workDir != "" {
				executor.Dir = workDir
			}

			// run
			executor.Stdout = os.Stdout
			executor.Stderr = os.Stderr
			executor.Run()

			// Flag: report-file
			var resultData, _ = json.MarshalIndent(executor.Result, "", "  ")
			var _ = os.WriteFile(reportFilePath, resultData, 0644)
			return nil
		},
	}

	runCommand.DisableFlagsInUseLine = true
	runCommand.Flags().StringVar(&policyFilePath, "policy-file", "", "use the specified policy configuration file")
	runCommand.Flags().StringVar(&reportFilePath, "report-file", "", "generate a JSON-formatted report at the specified location")
	runCommand.Flags().BoolVar(&verbose, "verbose", false, "turn on verbose mode")
	runCommand.Flags().StringVar(&workDir, "work-dir", "", "run PROGRAM under the specified directory")

	runCommand.Flags().StringVar(&policy, "policy", "_default", "use the specified policy")
	_ = runCommand.Flags().MarkHidden("policy")

	return runCommand
}
