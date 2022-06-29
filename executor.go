package gsandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/souk4711/gsandbox/prlimit"
)

type Executor struct {
	// Prog is the path of the command to run
	Prog string

	// Args holds command line arguments
	Args []string

	// Limits specifies resource limtis
	*Limits

	// Result contains information about an exited comamnd, available after a call to Run
	*Result

	// cmd is the underlying comamnd, once started
	cmd *exec.Cmd
}

func (e *Executor) Run() {
	e.setupCmdProg()
	e.setupCmdNamespace()

	e.run()
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
		Ptrace: true,
	}
}

func (e *Executor) setupRlimit(pid int) error {
	if e.Limits == nil {
		return nil
	}

	if lim := e.Limits.RlimitAS; lim != nil {
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_AS, &rlim); err != nil {
			return fmt.Errorf("rlimit: as: %s", err.Error())
		}
	}

	if lim := e.Limits.RlimitCPU; lim != nil {
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CPU, &rlim); err != nil {
			return fmt.Errorf("rlimit: cpu: %s", err.Error())
		}
	}

	if lim := e.Limits.RlimitCORE; lim != nil {
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CORE, &rlim); err != nil {
			return fmt.Errorf("rlimit: core: %s", err.Error())
		}
	}

	if lim := e.Limits.RlimitFSIZE; lim != nil {
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_FSIZE, &rlim); err != nil {
			return fmt.Errorf("rlimit: fsize: %s", err.Error())
		}
	}

	if lim := e.Limits.RlimitNOFILE; lim != nil {
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_NOFILE, &rlim); err != nil {
			return fmt.Errorf("rlimit: nofile: %s", err.Error())
		}
	}

	return nil
}

func (e *Executor) run() {
	var status Status
	var reason string
	var exitCode int
	var startTime time.Time
	var finishTime time.Time
	var systemTime time.Duration
	var userTime time.Duration
	var maxrss int64

	var setResult = func(ws *syscall.WaitStatus, usage *syscall.Rusage) {
		if ws != nil {
			if ws.Signaled() {
				switch ws.Signal() {
				case syscall.SIGXCPU, syscall.SIGKILL:
					status = StatusTimeLimitExceeded
				case syscall.SIGXFSZ:
					status = StatusOutputLimitExceeded
				case syscall.SIGSYS:
					status = StatusViolation
				default:
					status = StatusSignaled
				}

				reason = fmt.Sprintf("signal: %s", ws.Signal())
				exitCode = int(ws.Signal())
			}
		}

		if usage != nil {
			maxrss = usage.Maxrss
		}

		e.Result = &Result{
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

	startTime = time.Now()
	var err = e.cmd.Start()
	if err != nil {
		status = StatusExitFailure
		reason = err.Error()
		exitCode = e.cmd.ProcessState.ExitCode()
		setResult(nil, nil)
		return
	}

	if err := e.setupRlimit(e.cmd.Process.Pid); err != nil {
		e.Result = &Result{
			Status:   StatusSetupFailure,
			Reason:   err.Error(),
			ExitCode: -1,
		}
		return
	}

	var ws syscall.WaitStatus
	var usage syscall.Rusage
	if _, err = syscall.Wait4(e.cmd.Process.Pid, &ws, 0, &usage); err != nil {
		status = StatusExitFailure
		reason = err.Error()
		exitCode = e.cmd.ProcessState.ExitCode()
		setResult(nil, nil)
		return
	}

	finishTime = time.Now()
	status = StatusOK
	reason = ""
	exitCode = e.cmd.ProcessState.ExitCode()
	setResult(&ws, &usage)
}
