package gsandbox

import (
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"gopkg.in/yaml.v3"

	"github.com/souk4711/gsandbox/pkg/fsfilter"
)

type Sandbox struct {
	policy           Policy
	logger           logr.Logger
	runningExecutors map[*Executor]struct{}
}

func NewSandbox() *Sandbox {
	var s = Sandbox{
		logger:           funcr.New(func(_, _ string) {}, funcr.Options{}),
		runningExecutors: make(map[*Executor]struct{}),
	}
	return &s
}

func (s *Sandbox) WithLogger(logger logr.Logger) *Sandbox {
	s.logger = logger
	return s
}

func (s *Sandbox) NewExecutor(prog string, args []string) *Executor {
	var policy = s.policy
	var executor = NewExecutor(prog, args).WithLogger(s.logger)

	// env
	if policy.InheritEnv == ENABLED {
		var nilEnv []string
		executor.Env = nilEnv
	} else {
		executor.Env = make([]string, 0)
	}

	// work-dir
	if policy.WorkingDirectory != "" {
		executor.Dir = policy.WorkingDirectory
	}

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
	if duration, err := time.ParseDuration(policy.Limits.WALLCLOCK); err == nil {
		var v = uint64(duration.Seconds())
		limits.LimitWallClockTime = &v
	}
	executor.SetLimits(limits)

	// set allowed syscalls
	for _, syscall := range policy.AllowedSyscalls {
		executor.AddAllowedSyscall(syscall)
	}

	// set allowed files with perm
	executor.SetFilterFileList(fsfilter.FILE_RD, policy.FileSystem.ReadableFiles)
	executor.SetFilterFileList(fsfilter.FILE_WR, policy.FileSystem.WritableFiles)
	executor.SetFilterFileList(fsfilter.FILE_EX, policy.FileSystem.ExecutableFiles)

	// .
	executor.sandbox = s
	return executor
}

func (s *Sandbox) Cleanup() {
	for e := range s.runningExecutors {
		_ = syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL)
	}
	for e := range s.runningExecutors {
		_, _ = syscall.Wait4(-e.cmd.Process.Pid, nil, syscall.WALL, nil)
	}
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

func (s *Sandbox) addRunningExecutor(e *Executor) {
	s.runningExecutors[e] = struct{}{}
}

func (s *Sandbox) removeRunningExecutor(e *Executor) {
	delete(s.runningExecutors, e)
}
