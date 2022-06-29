package gsandbox

import (
	"runtime"
)

var (
	version = &Version{
		Name:      "Gsandbox",
		Number:    "0.0.1",
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		ARCH:      runtime.GOARCH,
	}
)

func GetVersion() *Version {
	return version
}

func Run(prog string, args []string) *Result {
	var e = &Executor{Prog: prog, Args: args}
	return e.Run()
}
