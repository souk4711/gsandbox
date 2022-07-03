package gsandbox

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/go-logr/logr"

	"github.com/souk4711/gsandbox/pkg/fsfilter"
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

	// fsfilter specifies the Filter
	fsfilter *fsfilter.FsFilter
	rdFiles  []string
	wrFiles  []string
	exFiles  []string

	// cmd is the underlying comamnd, once started
	cmd *exec.Cmd

	// logger
	logger logr.Logger
}

func NewExecutor(prog string, args []string) *Executor {
	var e = Executor{
		Prog: prog, Args: args,
		flags: make(map[string]string), allowedSyscalls: make(map[string]struct{}),
	}
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

func (e *Executor) SetFilterFileList(perm int, files []string) {
	switch perm {
	case fsfilter.FILE_RD:
		e.rdFiles = files
	case fsfilter.FILE_WR:
		e.wrFiles = files
	case fsfilter.FILE_EX:
		e.exFiles = files
	default:
		panic("invalid argument to SetFilerFileList")
	}
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

		e.logger.Info("proc: Exit:")
		e.logger.Info(fmt.Sprintf("          status: %d, %s", status, status))
		e.logger.Info(fmt.Sprintf("          reason: %s", reason))
		e.logger.Info(fmt.Sprintf("        exitCode: %d", exitCode))
		e.logger.Info(fmt.Sprintf("          startT: %s", startTime.Format(time.ANSIC)))
		e.logger.Info(fmt.Sprintf("         finishT: %s", finishTime.Format(time.ANSIC)))
		e.logger.Info(fmt.Sprintf("            real: %s", realTime))
		e.logger.Info(fmt.Sprintf("             sys: %s", systemTime))
		e.logger.Info(fmt.Sprintf("            user: %s", userTime))
		e.logger.Info(fmt.Sprintf("             rss: %s", humanize.IBytes(uint64(maxrss))))
	}

	var setResultWithOK = func(ws *syscall.WaitStatus, rusage *syscall.Rusage) {
		finishTime = time.Now()
		status = StatusOK
		reason = ""
		setResult(ws, rusage)
	}

	var setResultWithSandboxFailure = func(err error) {
		finishTime = time.Now()
		status = StatusSandboxFailure
		reason = err.Error()
		setResult(nil, nil)
		_ = cmd.Process.Kill() // ensure child process will not block the parent process
	}

	var setResultWithViolation = func(err error) {
		finishTime = time.Now()
		status = StatusViolation
		reason = err.Error()
		setResult(nil, nil)
		_ = cmd.Process.Kill() // ensure child process will not block the parent process
	}

	var setResultWithExecFailure = func(err error) {
		finishTime = time.Now()
		status = StatusExitFailure
		reason = err.Error()
		setResult(nil, nil)
	}

	// Because the go runtime forks traced processes with PTRACE_TRACEME
	// we need to maintain the parent-child relationship for ptrace to work.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// start a new process
	e.logger.Info(fmt.Sprintf("proc: Start: %s %s", e.Prog, strings.Join(e.Args, " ")))
	startTime = time.Now()
	if err := cmd.Start(); err != nil {
		setResultWithExecFailure(err)
		return
	}
	defer func() { // avoid child process become a zombie process
		_ = cmd.Wait()
	}()

	// set child process resource limit
	var pid = cmd.Process.Pid
	if err := e.setCmdRlimits(pid); err != nil {
		setResultWithSandboxFailure(err)
		return
	}

	// set fsfilter
	e.fsfilter = fsfilter.NewFsFilter(pid)
	for _, file := range e.rdFiles {
		if err := e.fsfilter.AddAllowedFile(file, fsfilter.FILE_RD); err != nil {
			setResultWithSandboxFailure(err)
			return
		}
	}
	for _, file := range e.wrFiles {
		if err := e.fsfilter.AddAllowedFile(file, fsfilter.FILE_WR); err != nil {
			setResultWithSandboxFailure(err)
			return
		}
	}
	for _, file := range e.exFiles {
		if err := e.fsfilter.AddAllowedFile(file, fsfilter.FILE_EX); err != nil {
			setResultWithSandboxFailure(err)
			return
		}
	}

	// start trace
	var ws syscall.WaitStatus
	var rusage syscall.Rusage
	var prev *ptrace.Syscall = nil
	var insyscall = false
	for {
		// check wait status
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

		// handle ptrace events
		curr, err := ptrace.GetSyscall(pid)
		if err != nil {
			setResultWithSandboxFailure(err)
			return
		}

		if insyscall { // syscall enter event
			result, err := e.applySyscallFilterWhenEnter(curr)
			if err != nil {
				setResultWithSandboxFailure(err)
				return
			}
			if result != nil {
				setResultWithViolation(result)
				return
			}
			prev = curr
			insyscall = false
		} else { // syscall exit event
			result, err := e.applySyscallFilterWhenExit(curr, prev)
			if err != nil {
				setResultWithSandboxFailure(err)
				return
			}
			if result != nil {
				setResultWithViolation(result)
				return
			}
			prev = nil
			insyscall = true
		}

		// Resume tracee execution. Make the kernel stop the child process whenever a
		// system call entry or exit is made.
		if err := syscall.PtraceSyscall(pid, 0); err != nil {
			err = fmt.Errorf("ptrace: Syscall: %s", err.Error())
			setResultWithSandboxFailure(err)
			return
		}
	}
}

func (e *Executor) setCmdRlimits(pid int) error {
	if lim := e.limits.RlimitAS; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit:     as => %s", humanize.IBytes(*lim)))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_AS, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetAS: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitCPU; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit:    cpu => %s", time.Duration(*lim*uint64(time.Second))))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CPU, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetCPU: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitCORE; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit:   core => %s", humanize.IBytes(*lim)))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CORE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetCORE: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitFSIZE; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit:  fsize => %s", humanize.IBytes(*lim)))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_FSIZE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetFSIZE: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitNOFILE; lim != nil {
		e.logger.Info(fmt.Sprintf("setrlimit: nofile => %d", *lim))

		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_NOFILE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetNOFILE: %s", err.Error())
		}
	}

	return nil
}
