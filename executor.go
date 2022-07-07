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

	// (rd|wr|ex)Files specifies file acesss rules
	rdFiles []string
	wrFiles []string
	exFiles []string

	// cmd is the underlying comamnd, once started
	cmd *exec.Cmd

	// .
	traceePid      int
	traceeFsfilter map[int]*fsfilter.FsFilter

	// logger
	logger logr.Logger
}

func NewExecutor(prog string, args []string) *Executor {
	var e = Executor{
		Prog: prog, Args: args,
		flags: make(map[string]string), allowedSyscalls: make(map[string]struct{}),
		traceeFsfilter: make(map[int]*fsfilter.FsFilter),
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

	// logging
	r := &e.Result
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
		Ptrace:       true, // required by ptrace
		Setpgid:      true, // required by ptrace
	}
}

func (e *Executor) run() {
	// start a new process
	e.Result.StartTime = time.Now()
	if err := e.cmd.Start(); err != nil {
		e.setResultWithExecFailure(err)
		return
	}
	defer func() { // avoid child process become a zombie process
		_ = e.cmd.Wait()
	}()

	// set child process resource limit
	var pid = e.cmd.Process.Pid
	if err := e.setCmdRlimits(pid); err != nil {
		e.setResultWithSandboxFailure(err)
		return
	}

	// set fsfilter
	if err := e.setFsFilter(pid); err != nil {
		e.setResultWithExecFailure(err)
		return
	}

	// start ptrace
	ptrace.Trace(pid, e)
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

func (e *Executor) setFsFilter(pid int) error {
	filter := fsfilter.NewFsFilter(pid)
	for _, file := range e.rdFiles {
		if err := filter.AddAllowedFile(file, fsfilter.FILE_RD); err != nil {
			return err
		}
	}
	for _, file := range e.wrFiles {
		if err := filter.AddAllowedFile(file, fsfilter.FILE_WR); err != nil {
			return err
		}
	}
	for _, file := range e.exFiles {
		if err := filter.AddAllowedFile(file, fsfilter.FILE_EX); err != nil {
			return err
		}
	}

	e.traceeFsfilter[pid] = filter
	return nil
}

func (e *Executor) setResult(ws *syscall.WaitStatus, rusage *syscall.Rusage) {
	r := &e.Result
	if ws != nil {
		if ws.Signaled() {
			switch ws.Signal() {
			case syscall.SIGXCPU, syscall.SIGKILL:
				r.Status = StatusTimeLimitExceeded
			case syscall.SIGXFSZ:
				r.Status = StatusOutputLimitExceeded
			case syscall.SIGSYS:
				r.Status = StatusViolation
			default:
				r.Status = StatusSignaled
			}

			r.Reason = fmt.Sprintf("signal: %s", ws.Signal())
			r.ExitCode = int(ws.Signal())
		} else {
			r.ExitCode = ws.ExitStatus()
		}
	} else {
		r.ExitCode = -1
	}

	if rusage != nil {
		r.SystemTime = time.Duration(rusage.Stime.Nano()) * time.Nanosecond
		r.UserTime = time.Duration(rusage.Utime.Nano()) * time.Nanosecond
		r.Maxrss = rusage.Maxrss
	}

	if r.FinishTime.IsZero() {
		r.FinishTime = time.Now()
		r.RealTime = r.FinishTime.Sub(r.StartTime)
	} else {
		r.RealTime = r.FinishTime.Sub(r.StartTime)
	}
}

func (e *Executor) setResultWithOK(ws *syscall.WaitStatus, rusage *syscall.Rusage) {
	r := &e.Result
	r.FinishTime = time.Now()
	r.Status = StatusOK
	r.Reason = ""
	e.setResult(ws, rusage)
}

func (e *Executor) setResultWithSandboxFailure(err error) {
	r := &e.Result
	r.FinishTime = time.Now()
	r.Status = StatusSandboxFailure
	r.Reason = err.Error()
	e.setResult(nil, nil)
	_ = e.cmd.Process.Kill() // ensure child process will not block the parent process
}

func (e *Executor) setResultWithViolation(err error) {
	r := &e.Result
	r.FinishTime = time.Now()
	r.Status = StatusViolation
	r.Reason = err.Error()
	e.setResult(nil, nil)
	_ = e.cmd.Process.Kill() // ensure child process will not block the parent process
}

func (e *Executor) setResultWithExecFailure(err error) {
	r := &e.Result
	r.FinishTime = time.Now()
	r.Status = StatusExitFailure
	r.Reason = err.Error()
	e.setResult(nil, nil)
}

func (e *Executor) info(msg string) {
	e.logger.Info(fmt.Sprintf("[%d] %s", e.traceePid, msg))
}
