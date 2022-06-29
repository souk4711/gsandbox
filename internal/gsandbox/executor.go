package gsandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/elastic/go-seccomp-bpf"
)

type Executor struct {
	// Prog is the path of the command to run
	Prog string

	// Args holds command line arguments
	Args []string

	// Limits specifies resource limtis
	Limits

	// SeccompPolicy specifies seccomp policy
	SeccompPolicy *seccomp.Policy

	//
	cmd *exec.Cmd
}

func (e *Executor) Run() *Result {
	e.setupCmdProg()
	e.setupCmdNamespace()

	if err := e.setupRlimit(); err != nil {
		return &Result{
			Status:   StatusSetupFailure,
			Reason:   err.Error(),
			ExitCode: -1,
		}
	}

	if err := e.setupSeccomp(); err != nil {
		return &Result{
			Status:   StatusSetupFailure,
			Reason:   err.Error(),
			ExitCode: -1,
		}
	}

	return e.run()
}

func (e *Executor) setupCmdProg() {
	e.cmd = exec.Command(e.Prog, e.Args...)
	e.cmd.Stdin = os.Stdin
	e.cmd.Stdout = os.Stdout
	e.cmd.Stderr = os.Stderr
}

func (e *Executor) setupCmdNamespace() {
	e.cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNS |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET |
			syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			},
		},
	}
}

func (e *Executor) setupRlimit() error {
	if lim := e.Limits.rlimitAS; lim != nil {
		var rlim = &syscall.Rlimit{Cur: lim.Value, Max: lim.Value}
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, rlim); err != nil {
			return fmt.Errorf("rlimit: as: %s", err.Error())
		}
	}

	if lim := e.Limits.rlimitCPU; lim != nil {
		var rlim = &syscall.Rlimit{Cur: lim.Value, Max: lim.Value}
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, rlim); err != nil {
			return fmt.Errorf("rlimit: cpu: %s", err.Error())
		}
	}

	if lim := e.Limits.rlimitCORE; lim != nil {
		var rlim = &syscall.Rlimit{Cur: lim.Value, Max: lim.Value}
		if err := syscall.Setrlimit(syscall.RLIMIT_CORE, rlim); err != nil {
			return fmt.Errorf("rlimit: core: %s", err.Error())
		}
	}

	if lim := e.Limits.rlimitFSIZE; lim != nil {
		var rlim = &syscall.Rlimit{Cur: lim.Value, Max: lim.Value}
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, rlim); err != nil {
			return fmt.Errorf("rlimit: fsize: %s", err.Error())
		}
	}

	if lim := e.Limits.rlimitNOFILE; lim != nil {
		var rlim = &syscall.Rlimit{Cur: lim.Value, Max: lim.Value}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, rlim); err != nil {
			return fmt.Errorf("rlimit: nofile: %s", err.Error())
		}
	}

	return nil
}

func (e *Executor) setupSeccomp() error {
	if e.SeccompPolicy != nil {
		var filter = seccomp.Filter{
			NoNewPrivs: true,
			Flag:       seccomp.FilterFlagTSync,
			Policy:     *e.SeccompPolicy,
		}
		if err := seccomp.LoadFilter(filter); err != nil {
			return fmt.Errorf("seccomp: %s", err.Error())
		}
	}

	return nil
}

func (e *Executor) run() *Result {
	var status Status
	var reason string
	var exitCode int
	var startTime time.Time
	var finishTime time.Time
	var systemTime time.Duration
	var userTime time.Duration
	var maxrss int64

	startTime = time.Now()
	var err = e.cmd.Run()
	finishTime = time.Now()

	if err != nil {
		status = StatusExitFailure
		reason = err.Error()
		exitCode = e.cmd.ProcessState.ExitCode()
	} else {
		status = StatusOK
		reason = ""
		exitCode = e.cmd.ProcessState.ExitCode()
	}

	var stat = e.cmd.ProcessState
	if stat != nil {
		systemTime = stat.SystemTime()
		userTime = stat.UserTime()

		var w = stat.Sys()
		if w, ok := w.(syscall.WaitStatus); ok {
			if w.Signaled() {
				switch w.Signal() {
				case syscall.SIGXCPU, syscall.SIGKILL:
					status = StatusTimeLimitExceeded
				case syscall.SIGXFSZ:
					status = StatusOutputLimitExceeded
				case syscall.SIGSYS:
					status = StatusViolation
				default:
					status = StatusSignaled
				}

				reason = fmt.Sprintf("signal: %s", w.Signal())
				exitCode = int(w.Signal())
			}
		}

		var usage = stat.SysUsage()
		if usage, ok := usage.(*syscall.Rusage); ok {
			maxrss = usage.Maxrss
		}
	}

	return &Result{
		Status:     status,
		Reason:     reason,
		ExitCode:   exitCode,
		StartTime:  startTime,
		FinishTime: finishTime,
		RealTime:   finishTime.Sub(startTime),
		SystemTime: systemTime,
		UserTime:   userTime,
		Maxrss:     maxrss,
	}
}
