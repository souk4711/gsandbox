package gsandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"

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

	// Env specifies the environment of the process, plz see os/exec.Cmd#Env
	Env []string

	// Stdin specifies the process's standard input, plz see os/exec.Cmd#Stdin
	Stdin io.Reader

	// Stdout specify the process's standard output, plz see os/exec.Cmd#Stdout
	Stdout io.Writer

	// Stderr specify the process's standard error, plz see os/exec.Cmd#Stderr
	Stderr io.Writer

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

	// multiple processes info
	wpid           int
	wpid2Insyscall map[int]bool
	wpid2Prev      map[int]*ptrace.Syscall
	// wpid2Fsfilter map[int]*fsfilter.FsFilter

	// cmd is the underlying comamnd, once started
	cmd *exec.Cmd

	// logger
	logger logr.Logger
}

func NewExecutor(prog string, args []string) *Executor {
	var e = Executor{
		Prog: prog, Args: args,
		flags: make(map[string]string), allowedSyscalls: make(map[string]struct{}),
		wpid2Insyscall: make(map[int]bool), wpid2Prev: make(map[int]*ptrace.Syscall),
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
	// Because the go runtime forks traced processes with PTRACE_TRACEME
	// we need to maintain the parent-child relationship for ptrace to work.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// logging
	e.info(fmt.Sprintf("proc: Start: %s %s", e.Prog, strings.Join(e.Args, " ")))

	// timeout
	var cmd *exec.Cmd
	if lim := e.limits.LimitWallClockTime; lim != nil {
		e.info(fmt.Sprintf("setrlimit: walltime => %s", time.Duration(*lim*uint64(time.Second))))
		var ctx, cancel = context.WithTimeout(context.Background(), time.Duration(*lim)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, e.Prog, e.Args...)
	} else {
		cmd = exec.Command(e.Prog, e.Args...)
	}

	// env, stdin, stdout, stderr
	cmd.Env = e.Env
	cmd.Stdin = e.Stdin
	cmd.Stdout = e.Stdout
	cmd.Stderr = e.Stderr

	// proc-attr
	e.cmd = cmd
	e.setCmdProcAttr()

	// run
	e.run()
	e.wpid = 0

	// logging
	r := e.Result
	e.info("proc: Finished:")
	e.info(fmt.Sprintf("        status: %d, %s", r.Status, r.Status))
	e.info(fmt.Sprintf("        reason: %s", r.Reason))
	e.info(fmt.Sprintf("      exitCode: %d", r.ExitCode))
	e.info(fmt.Sprintf("        startT: %s", r.StartTime.Format(time.ANSIC)))
	e.info(fmt.Sprintf("       finishT: %s", r.FinishTime.Format(time.ANSIC)))
	e.info(fmt.Sprintf("          real: %s", r.RealTime))
	e.info(fmt.Sprintf("           sys: %s", r.SystemTime))
	e.info(fmt.Sprintf("          user: %s", r.UserTime))
	e.info(fmt.Sprintf("           rss: %s", humanize.IBytes(uint64(r.Maxrss))))
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
		Cloneflags:   uintptr(cloneFlags),
		Unshareflags: syscall.CLONE_NEWNS,
		UidMappings:  uidMappings,
		GidMappings:  gidMappings,
		Ptrace:       true,
		Setpgid:      true,
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
	var realTime time.Duration
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

		if finishTime.IsZero() {
			finishTime = time.Now()
			realTime = finishTime.Sub(startTime)
		} else {
			realTime = finishTime.Sub(startTime)
		}

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

	// start a new process
	startTime = time.Now()
	if err := cmd.Start(); err != nil {
		setResultWithExecFailure(err)
		return
	}
	defer func() { // avoid child process become a zombie process
		_ = cmd.Wait()
	}()

	// set trace options
	var pid = cmd.Process.Pid
	var flag = 0
	flag = flag | syscall.PTRACE_O_TRACESYSGOOD // makes it easy for the tracer to distinguish normal traps from those caused by a system call
	flag = flag | syscall.PTRACE_O_TRACEEXIT    // stop the tracee at exit
	//flag = flag | syscall.PTRACE_O_TRACECLONE   // automatically trace clone(2) children
	flag = flag | syscall.PTRACE_O_TRACEFORK  // automatically trace fork(2) children
	flag = flag | syscall.PTRACE_O_TRACEVFORK // automatically trace vfork(2) children
	if err := syscall.PtraceSetOptions(pid, flag); err != nil {
		setResultWithSandboxFailure(err)
		return
	}

	// set child process resource limit
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
	var prev *ptrace.Syscall
	var insyscall bool
	var firstClone = true
	for {
		wpid, err := syscall.Wait4(-pid, &ws, 0, &rusage)
		if err != nil {
			setResultWithSandboxFailure(err)
			return
		}

		// reterive process info
		e.wpid = wpid
		if v, ok := e.wpid2Insyscall[wpid]; ok {
			insyscall = v
		} else {
			insyscall = true
		}
		if v, ok := e.wpid2Prev[wpid]; ok {
			prev = v
		} else {
			prev = nil
		}

		// check wait status
		if e.wpid == pid {
			if ws.Exited() {
				setResultWithOK(&ws, &rusage)
				return
			} else if ws.Signaled() {
				setResult(&ws, &rusage)
				return
			} else if ws.Stopped() {
				_ = ws.Signal()
			}
		}

		// handle ptrace events
		curr, err := ptrace.GetSyscall(e.wpid)

		if err != nil {
			setResultWithSandboxFailure(err)
			return
		}
		if insyscall { // syscall enter event
			// special case
			switch curr.GetNR() {
			case unix.SYS_EXECVE, unix.SYS_EXECVEAT: // Is an additional notification event of `exec`?
				if err := curr.GetRetval().Read(); err != nil {
					setResultWithSandboxFailure(err)
					return
				}
				if curr.GetRetval().GetValue() == 0 {
					goto TRACE_CONTINUE
				}
			case unix.SYS_CLONE:
				if err := curr.GetRetval().Read(); err != nil {
					setResultWithSandboxFailure(err)
					return
				}
				if curr.GetRetval().GetValue() == 0 { // Is an additional notification event of `clone`? - for child?
					goto TRACE_CONTINUE
				} else if curr.GetRetval().GetValue() == -38 && firstClone { // Is an additional notification event of `clone`? - for parent?
					firstClone = false
					goto TRACE_CONTINUE
				}
			}

			// filter
			result, err := e.applySyscallFilterWhenEnter(curr)
			if err != nil {
				setResultWithSandboxFailure(err)
				return
			}
			if result != nil {
				setResultWithViolation(result)
				return
			}
			e.wpid2Prev[e.wpid] = curr
			e.wpid2Insyscall[e.wpid] = false
		} else { // syscall leave event
			// special case
			switch curr.GetNR() {
			case unix.SYS_EXIT_GROUP:
				goto TRACE_CONTINUE
			}

			// filter
			result, err := e.applySyscallFilterWhenLeave(curr, prev)
			if err != nil {
				setResultWithSandboxFailure(err)
				return
			}
			if result != nil {
				setResultWithViolation(result)
				return
			}
			e.wpid2Prev[e.wpid] = nil
			e.wpid2Insyscall[e.wpid] = true
		}

	TRACE_CONTINUE:
		// Resume tracee execution. Make the kernel stop the child process whenever a
		// system call entry or exit is made.
		if err := syscall.PtraceSyscall(e.wpid, 0); err != nil {
			err = fmt.Errorf("ptrace: Syscall: %s", err.Error())
			setResultWithSandboxFailure(err)
			return
		}
	}
}

func (e *Executor) setCmdRlimits(pid int) error {
	if lim := e.limits.RlimitAS; lim != nil {
		e.info(fmt.Sprintf("setrlimit:       as => %s", humanize.IBytes(*lim)))
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_AS, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetAS: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitCPU; lim != nil {
		e.info(fmt.Sprintf("setrlimit:      cpu => %s", time.Duration(*lim*uint64(time.Second))))
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CPU, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetCPU: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitCORE; lim != nil {
		e.info(fmt.Sprintf("setrlimit:     core => %s", humanize.IBytes(*lim)))
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_CORE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetCORE: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitFSIZE; lim != nil {
		e.info(fmt.Sprintf("setrlimit:    fsize => %s", humanize.IBytes(*lim)))
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_FSIZE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetFSIZE: %s", err.Error())
		}
	}

	if lim := e.limits.RlimitNOFILE; lim != nil {
		e.info(fmt.Sprintf("setrlimit:   nofile => %d", *lim))
		var rlim = syscall.Rlimit{Cur: *lim, Max: *lim}
		if err := prlimit.Setprlimit(pid, syscall.RLIMIT_NOFILE, &rlim); err != nil {
			return fmt.Errorf("setrlimit: SetNOFILE: %s", err.Error())
		}
	}

	return nil
}

func (e *Executor) info(msg string) {
	e.logger.Info(fmt.Sprintf("[%d] %s", e.wpid, msg))
}
