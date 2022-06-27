package cmd

import (
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/souk4711/gsandbox"
)

const versionStringFormat = ("" +
	"Name:        Gsandbox\n" +
	"Version:     %s\n" +
	"Go Version:  %s\n" +
	"Git Commit:  %s\n" +
	"Built:       %s\n" +
	"OS/Arch:     %s/%s\n")

func newVersionCommand(gitCommit string, builtTime int64) *cobra.Command {
	var built = ""
	if builtTime != 0 {
		built = time.Unix(builtTime, 0).Format(time.ANSIC)
	}

	var versionCommand = &cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(
				versionStringFormat,
				gsandbox.Version(),
				runtime.Version(),
				gitCommit,
				built,
				runtime.GOOS, runtime.GOARCH,
			)
		},
	}

	return versionCommand
}
