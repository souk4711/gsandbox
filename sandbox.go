package gsandbox

import (
	_ "embed"
	"os"
	"runtime"

	"github.com/goccy/go-json"
	"github.com/imdario/mergo"
)

var (
	version = Version{
		Name:      "Gsandbox",
		Number:    "0.0.1",
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		ARCH:      runtime.GOARCH,
	}
)

var (
	//go:embed embed/policy.json
	defaultPolicyData []byte
)

func GetVersion() *Version {
	return &version
}

// Since Golang heavily uses OS-level threads to power its goroutine scheduling. There
// is no easy way to set resource limit or seccomp filter in child process. Set it in
// parent process, then inherits it.
//
// Plz see https://stackoverflow.com/questions/28370646/how-do-i-fork-a-go-process
func Run(prog string, args []string, policyFilePath string, limits Limits) (*Executor, error) {
	var policy Policy
	if err := runBuildPolicyFromPath(policyFilePath, &policy); err != nil {
		return nil, err
	}

	var executor = Executor{Prog: prog, Args: args}
	if err := runSetExecutorLimits(&executor, policy, limits); err != nil {
		return nil, err
	}

	executor.Run()
	return &executor, nil
}

func runBuildPolicyFromPath(policyFilePath string, policy *Policy) error {
	var policyData []byte
	if policyFilePath != "" {
		data, err := os.ReadFile(policyFilePath)
		if err != nil {
			return err
		}

		policyData = data
	} else {
		policyData = defaultPolicyData
	}

	if err := json.Unmarshal(policyData, policy); err != nil {
		return err
	}

	return nil
}

func runSetExecutorLimits(executor *Executor, policy Policy, limits Limits) error {
	executor.Limits = &Limits{}

	if err := mergo.Merge(executor.Limits, policy.Limits); err != nil {
		return err
	}
	if err := mergo.Merge(executor.Limits, limits); err != nil {
		return err
	}

	return nil
}
