package gsandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/souk4711/gsandbox/pkg/prlimit"
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
	var cmd = exec.Command(e.Prog, e.Args...)
	e.cmd = cmd

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
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

	e.run()
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
	var cmd = e.cmd

	var setResult = func(ws *syscall.WaitStatus, rusage *syscall.Rusage) {
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
			} else {
				exitCode = ws.ExitStatus()
			}
		} else {
			exitCode = -1
		}

		if rusage != nil {
			systemTime = time.Duration(rusage.Stime.Nano()) * time.Nanosecond
			userTime = time.Duration(rusage.Utime.Nano()) * time.Nanosecond
			maxrss = rusage.Maxrss
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

	var setResultWithExecFailure = func(ws *syscall.WaitStatus, rusage *syscall.Rusage, err error) {
		finishTime = time.Now()
		status = StatusExitFailure
		reason = err.Error()
		setResult(ws, rusage)
	}

	var setResultWithOK = func(ws *syscall.WaitStatus, rusage *syscall.Rusage) {
		finishTime = time.Now()
		status = StatusOK
		reason = ""
		setResult(ws, rusage)
	}

	startTime = time.Now()
	if err := cmd.Start(); err != nil {
		setResultWithExecFailure(nil, nil, err)
		return
	}

	var pid = cmd.Process.Pid
	if err := e.setCmdRlimits(pid); err != nil {
		var _ = cmd.Process.Kill()
		var _, _ = cmd.Process.Wait()
		setResultWithExecFailure(nil, nil, err)
		return
	}

	var ws syscall.WaitStatus
	var rusage syscall.Rusage
	for {
		if _, err := syscall.Wait4(pid, &ws, 0, &rusage); err != nil {
			setResultWithExecFailure(&ws, &rusage, err)
			return
		}

		if ws.Exited() {
			setResultWithOK(&ws, &rusage)
			return
		}

		if err := syscall.PtraceSyscall(pid, 0); err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			setResultWithExecFailure(&ws, &rusage, err)
			return
		}
	}
}

func (e *Executor) setCmdRlimits(pid int) error {
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
