package gsandbox

import (
	"os"
	"strconv"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"gopkg.in/yaml.v3"
)

type Sandbox struct {
	policy Policy
	logger logr.Logger
}

func NewSandbox() *Sandbox {
	var s = Sandbox{logger: funcr.New(func(_, _ string) {}, funcr.Options{})}
	return &s
}

func (s *Sandbox) WithLogger(logger logr.Logger) *Sandbox {
	s.logger = logger
	return s
}

func (s *Sandbox) Run(prog string, args []string) *Executor {
	var policy = s.policy
	var executor = NewExecutor(prog, args).WithLogger(s.logger)

	// set flags
	if policy.ShareNetwork == ENABLED {
		executor.SetFlag(FLAG_SHARE_NETWORK, ENABLED)
	}

	// set limits
	var limits = Limits{}
	if v, err := humanize.ParseBytes(policy.Limits.AS); err == nil {
		limits.RlimitAS = &v
	}
	if v, err := humanize.ParseBytes(policy.Limits.CORE); err == nil {
		limits.RlimitCORE = &v
	}
	if duration, err := time.ParseDuration(policy.Limits.CPU); err == nil {
		var v = uint64(duration.Seconds())
		limits.RlimitCPU = &v
	}
	if v, err := humanize.ParseBytes(policy.Limits.FSIZE); err == nil {
		limits.RlimitFSIZE = &v
	}
	if v, err := strconv.ParseUint(policy.Limits.NOFILE, 10, 64); err == nil {
		limits.RlimitNOFILE = &v
	}
	executor.SetLimits(limits)

	// set allowed syscalls
	for _, syscall := range policy.AllowedSyscalls {
		executor.AddAllowedSyscall(syscall)
	}

	executor.Run()
	return executor
}

func (s *Sandbox) LoadPolicyFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if err := s.LoadPolicyFromData(data); err != nil {
		return err
	}
	return nil
}

func (s *Sandbox) LoadPolicyFromData(data []byte) error {
	return yaml.Unmarshal(data, &s.policy)
}
