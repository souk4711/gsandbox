package cmd

import (
	"os"
	"strconv"

	"github.com/goccy/go-json"
	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox/internal/gsandbox"
)

func newRunCommand() *cobra.Command {
	var policyFilePath string
	var reportFilePath string
	var limitAS string
	var limitCORE string
	var limitCPU string
	var limitFSIZE string
	var limitNOFILE string

	var setLimits = func(limits *gsandbox.Limits) error {
		if limitAS != "" {
			if value, err := strconv.ParseUint(limitAS, 10, 64); err != nil {
				return err
			} else {
				limits.RlimitAS = &value
			}
		}

		if limitCORE != "" {
			if value, err := strconv.ParseUint(limitCORE, 10, 64); err != nil {
				return err
			} else {
				limits.RlimitCORE = &value
			}
		}

		if limitCPU != "" {
			if value, err := strconv.ParseUint(limitCPU, 10, 64); err != nil {
				return err
			} else {
				limits.RlimitCPU = &value
			}
		}

		if limitFSIZE != "" {
			if value, err := strconv.ParseUint(limitFSIZE, 10, 64); err != nil {
				return err
			} else {
				limits.RlimitFSIZE = &value
			}
		}

		if limitNOFILE != "" {
			if value, err := strconv.ParseUint(limitNOFILE, 10, 64); err != nil {
				return err
			} else {
				limits.RlimitNOFILE = &value
			}
		}

		return nil
	}

	var runCommand = &cobra.Command{
		Use:   "run [flags] -- PROGRAM [ARG...]",
		Short: "Run a program in a sandbox",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var limits gsandbox.Limits
			if err := setLimits(&limits); err != nil {
				return err
			}

			executor, err := gsandbox.Run(args[0], args[1:], policyFilePath, limits)
			if err != nil {
				return err
			}

			resultData, err := json.Marshal(&executor.Result)
			if err != nil {
				return err
			}

			if err := os.WriteFile(reportFilePath, resultData, 0644); err != nil {
				return err
			}

			return nil
		},
	}

	runCommand.DisableFlagsInUseLine = true
	runCommand.Flags().StringVar(&policyFilePath, "policy-file", "", "use the specified policy configuration file")
	runCommand.Flags().StringVar(&reportFilePath, "report-file", "proc-metadata.json", "generate a JSON-formatted report at the specified location")
	runCommand.Flags().StringVar(&limitAS, "limit-as", "", "the maximum size of virtual memory (address space) in bytes")
	runCommand.Flags().StringVar(&limitCORE, "limit-core", "", "the maximum size of core files created")
	runCommand.Flags().StringVar(&limitCPU, "limit-cpu", "", "the maximum amount of cpu time in seconds")
	runCommand.Flags().StringVar(&limitFSIZE, "limit-fsize", "", "the maximum size of files written by the shell and its children")
	runCommand.Flags().StringVar(&limitNOFILE, "limit-nofile", "", "the maximum number of open file descriptors")

	return runCommand
}
