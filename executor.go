package gsandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/souk4711/gsandbox/pkg/prlimit"
	"github.com/souk4711/gsandbox/pkg/ptrace"
)

type Executor struct {
	// Prog is the path of the command to run
	Prog string

	// Args holds command line arguments
	Args []string

	// Limits specifies resource limtis
	Limits

	// AllowedSyscalls specifies the calls that are allowed
	AllowedSyscalls map[string]struct{}

	// Result contains information about an exited comamnd, available after a call to #Run
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

	var setResultWithOK = func(ws *syscall.WaitStatus, rusage *syscall.Rusage) {
		finishTime = time.Now()
		status = StatusOK
		reason = ""
		setResult(ws, rusage)
	}

	var setResultWithSetupFailure = func(err error) {
		finishTime = time.Now()
		status = StatusSetupFailure
		reason = err.Error()
		setResult(nil, nil)
		_ = cmd.Process.Kill() // Ensure child process will not block the parent process
	}

	var setResultWithViolation = func(err error) {
		finishTime = time.Now()
		status = StatusViolation
		reason = err.Error()
		setResult(nil, nil)
		_ = cmd.Process.Kill() // Ensure child process will not block the parent process
	}

	var setResultWithExecFailure = func(err error) {
		finishTime = time.Now()
		status = StatusExitFailure
		reason = err.Error()
		setResult(nil, nil)
	}

	// Start a new process
	startTime = time.Now()
	if err := cmd.Start(); err != nil {
		setResultWithExecFailure(err)
		return
	}
	defer func() { // Avoid child process become a zombie process
		_ = cmd.Wait()
	}()

	// Set child process resource limit
	var pid = cmd.Process.Pid
	if err := e.setCmdRlimits(pid); err != nil {
		setResultWithSetupFailure(err)
		return
	}

	var ws syscall.WaitStatus
	var rusage syscall.Rusage
	var insyscall = false
	for {
		// Check wait status
		_, _ = syscall.Wait4(pid, &ws, 0, &rusage)
		if ws.Exited() {
			setResultWithOK(&ws, &rusage)
			return
		} else if ws.Signaled() {
			setResult(&ws, &rusage)
			return
		} else if ws.Stopped() {
			_ = ws.Signal()
		}

		// Handle ptrace events
		ptraceSyscall, err := ptrace.GetPtraceSyscall(pid)
		if err != nil {
			setResultWithSetupFailure(err)
			return
		}

		if insyscall { // Syscall enter
			insyscall = false
			if _, ok := e.AllowedSyscalls[ptraceSyscall.Name]; !ok {
				err := fmt.Errorf("syscall denied: %s", ptraceSyscall.Name)
				setResultWithViolation(err)
				return
			}
		} else { // Syscall exit
			insyscall = true
		}

		// Resume tracee execution. Make the kernel stop the child process whenever a
		// system call entry or exit is made
		if err := syscall.PtraceSyscall(pid, 0); err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			setResultWithSetupFailure(err)
			return
		}
	}
}

func (e *Executor) setCmdRlimits(pid int) error {
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
