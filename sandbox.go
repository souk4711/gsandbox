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

func (s *Sandbox) Policy() *Policy {
	if s.policy == nil {
		_ = s.LoadPolicyFromData(defaultPolicyData)
	}

	return s.policy
}

func (s *Sandbox) Run(prog string, args []string) *Executor {
	var executor = Executor{Prog: prog, Args: args, Limits: &s.Policy().Limits}
	executor.Run()
	return &executor
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
