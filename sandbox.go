package gsandbox

import (
	_ "embed"
	"os"

	"gopkg.in/yaml.v3"
)

var (
	//go:embed policy.yml
	defaultPolicyData []byte
)

type Sandbox struct {
	policy *Policy
}

func NewSandbox() *Sandbox {
	var s = Sandbox{}
	return &s
}

func (s *Sandbox) Run(prog string, args []string) *Executor {
	if s.policy == nil {
		_ = s.LoadPolicyFromData(defaultPolicyData)
	}

	var executor = NewExecutor(prog, args)

	// set Flags
	if s.policy.ShareNetwork == ENABLED {
		executor.SetFlag(FLAG_SHARE_NETWORK, ENABLED)
	}

	// set limits
	executor.SetLimits(s.policy.Limits)

	// set allowedSyscalls
	for _, syscall := range s.policy.AllowedSyscalls {
		executor.AddAllowedSyscall(syscall)
	}

	executor.Run()
	return executor
}

func (s *Sandbox) LoadPolicyFromFile(filePath string) error {
	var data, err = os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if err := s.LoadPolicyFromData(data); err != nil {
		return err
	}
	return nil
}

func (s *Sandbox) LoadPolicyFromData(data []byte) error {
	s.policy = &Policy{}
	return yaml.Unmarshal(data, s.policy)
}
