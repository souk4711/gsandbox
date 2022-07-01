package gsandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/go-logr/logr"

	"github.com/souk4711/gsandbox/pkg/prlimit"
	"github.com/souk4711/gsandbox/pkg/ptrace"
)

const (
	// flag names
	FLAG_SHARE_NETWORK = "share-net"

	// flag values
	ENABLED = "enabled"
)

type Executor struct {
	// Prog is the path of the command to run
	Prog string

	// Args holds command line arguments
	Args []string

	// Result contains information about an exited comamnd, available after a call to #Run
	Result

	// flags
	flags map[string]string

	// limits specifies resource limtis
	limits Limits

	// allowedSyscalls specifies the calls that are allowed
	allowedSyscalls map[string]struct{}

	// cmd is the underlying comamnd, once started
	cmd *exec.Cmd

	// logger
	logger logr.Logger
}

func NewExecutor(prog string, args []string) *Executor {
	var e = Executor{Prog: prog, Args: args, flags: make(map[string]string), allowedSyscalls: make(map[string]struct{})}
	return &e
}

func (e *Executor) WithLogger(logger logr.Logger) *Executor {
	e.logger = logger
	return e
}

func (e *Executor) SetFlag(name string, value string) {
	e.flags[name] = value
}

func (e *Executor) SetLimits(limits Limits) {
	e.limits = limits
}

func (e *Executor) AddAllowedSyscall(syscallName string) {
	e.allowedSyscalls[syscallName] = struct{}{}
}

func (e *Executor) Run() {
	var cmd = exec.Command(e.Prog, e.Args...)
	e.cmd = cmd

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	e.setCmdProcAttr()
	e.run()
}

func (e *Executor) setCmdProcAttr() {
	var cloneFlags = syscall.CLONE_NEWNS |
		syscall.CLONE_NEWUTS |
		syscall.CLONE_NEWIPC |
		syscall.CLONE_NEWPID |
		syscall.CLONE_NEWNET |
		syscall.CLONE_NEWUSER
	if e.flags[FLAG_SHARE_NETWORK] == ENABLED {
		cloneFlags = cloneFlags &^ syscall.CLONE_NEWNET
	}

	var uidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getuid(), Size: 1},
	}
	var gidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getgid(), Size: 1},
	}

	e.cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  uintptr(cloneFlags),
		UidMappings: uidMappings,
		GidMappings: gidMappings,
		Ptrace:      true,
	}
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

		var realTime = finishTime.Sub(startTime)
		e.Result = Result{
			Status:     status,
			Reason:     reason,
			ExitCode:   exitCode,
			StartTime:  startTime,
			FinishTime: finishTime,
			RealTime:   realTime,
			SystemTime: systemTime,
			UserTime:   userTime,
			Maxrss:     maxrss,
		}

		e.logger.Info(fmt.Sprintf(
			"proc-exit: status(%d, %s), reason(%s), exitCode(%d), startT(%s), finishT(%s), real(%s), sys(%s), user(%s), rss(%s)",
			status, status, reason, exitCode, startTime.Format(time.ANSIC), finishTime.Format(time.ANSIC), realTime, systemTime, userTime, humanize.IBytes(uint64(maxrss)),
		))
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
	e.logger.Info(fmt.Sprintf("proc-start: prog(%s), args(%s)", e.Prog, e.Args))
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
		ptraceSyscall, err := ptrace.GetSyscall(pid)
		if err != nil {
			setResultWithSetupFailure(err)
			return
		}

		if insyscall { // Syscall enter event
			insyscall = false
			if err := e.runSyscallFilter(ptraceSyscall); err != nil {
				setResultWithViolation(err)
				return
			}
		} else { // Syscall exit event
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
	if lim := e.limits.RlimitAS; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit: as(%s)", humanize.IBytes(*lim)))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_AS, &rlim); err != nil {
			return fmt.Errorf("setrlimit: as: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitCPU; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit: cpu(%s)", time.Duration(*lim)))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CPU, &rlim); err != nil {
			return fmt.Errorf("setrlimit: cpu: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitCORE; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit: core(%s)", humanize.IBytes(*lim)))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CORE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: core: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitFSIZE; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit: fsize(%s)", humanize.IBytes(*lim)))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_FSIZE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: fsize: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitNOFILE; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit: nofile(%d)", *lim))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_NOFILE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: nofile: %s", err.Error())
		}
	}

	return nil
}

func (e *Executor) runSyscallFilter(ptraceSyscall *ptrace.Syscall) error {
	var name = ptraceSyscall.GetName()
	e.logger.Info(fmt.Sprintf("syscall: func(%s)", name))

	if _, ok := e.allowedSyscalls[name]; !ok {
		err := fmt.Errorf("syscall: disallowed func(%s)", name)
		return err
	}
	return nil
}
