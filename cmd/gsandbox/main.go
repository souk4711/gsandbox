package main

import (
	"strconv"

	"github.com/souk4711/gsandbox/internal/cmd"
)

var (
	GitCommit = ""
	BuiltTime = ""
)

func main() {
	builtTime, _ := strconv.ParseInt(BuiltTime, 10, 64)
	cmd.Execute(GitCommit, builtTime)
}
