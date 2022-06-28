package gsandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type Executor struct {
	Prog string
	Args []string

	cmd *exec.Cmd
	res *Result
}

func (e *Executor) Run() *Result {
	e.setupCmdProg()
	e.setupCmdStream()
	e.setupCmdNamespace()
	e.run()

	return e.res
}

func (e *Executor) setupCmdProg() {
	e.cmd = exec.Command(e.Prog, e.Args...)
}

func (e *Executor) setupCmdStream() {
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

func (e *Executor) run() {
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
				case syscall.SIGXCPU:
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

	e.res = &Result{
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
