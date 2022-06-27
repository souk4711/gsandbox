package main

import (
	"strconv"

	"github.com/souk4711/gsandbox"
	"github.com/souk4711/gsandbox/internal/cmd"
)

var (
	GitCommit = ""
	BuiltTime = ""
)

func main() {
	var version = gsandbox.GetVersion()
	version.GitCommit = GitCommit

	if builtTime, err := strconv.ParseInt(BuiltTime, 10, 64); err == nil {
		version.BuiltTime = builtTime
	}

	cmd.Execute()
}
