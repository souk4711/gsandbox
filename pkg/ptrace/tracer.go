package ptrace

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func Trace(pid int, handler TracerHandler) {
	var tracer = Tracer{pid: pid, tracees: make(map[int]*Tracee)}
	tracer.trace(handler)
}

type TracerHandler interface {
	HandleTracerLogging(pid int, msg string)                                              // logging
	HandleTracerPanicEvent(err error)                                                     // panic
	HandleTracerExitedEvent(pid int, ws syscall.WaitStatus, rusage syscall.Rusage)        // ws.Exited()
	HandleTracerSignaledEvent(pid int, ws syscall.WaitStatus, rusage syscall.Rusage)      // ws.Signaled()
	HandleTracerNewChildEvent(pid int, childPid int)                                      // PTRACE_EVENT_CLONE
	HandleTracerSyscallEnterEvent(pid int, curr *Syscall) (continued bool)                // when syscall enter
	HandleTracerSyscallLeaveEvent(pid int, curr *Syscall, prev *Syscall) (continued bool) // when syscall leave
}

type Tracer struct {
	pid     int
	tracees map[int]*Tracee
}

func (t *Tracer) trace(handler TracerHandler) {
	var flag = 0
	flag = flag | syscall.PTRACE_O_TRACESYSGOOD // makes it easy for the tracer to distinguish normal traps from those caused by a system call
	flag = flag | syscall.PTRACE_O_TRACECLONE   // automatically trace clone(2) children
	flag = flag | syscall.PTRACE_O_TRACEFORK    // automatically trace fork(2) children
	flag = flag | syscall.PTRACE_O_TRACEVFORK   // automatically trace vfork(2) children
	flag = flag | syscall.PTRACE_O_TRACEEXIT    // stop the tracee at exit
	if err := syscall.PtraceSetOptions(t.pid, flag); err != nil {
		err := fmt.Errorf("PtraceSetOptions: %s", err)
		handler.HandleTracerLogging(t.pid, err.Error())
		handler.HandleTracerPanicEvent(err)
		return
	}

	var ws syscall.WaitStatus
	var rusage syscall.Rusage
	var currTracee *Tracee
	var curr *Syscall
	for {
		wpid, err := syscall.Wait4(-t.pid, &ws, syscall.WALL, &rusage)
		if err != nil {
			err := fmt.Errorf("Wait: %s", err)
			handler.HandleTracerLogging(t.pid, err.Error())
			handler.HandleTracerPanicEvent(err)
			return
		}

		// check wait status - WIFEXITED
		if ws.Exited() {
			msg := fmt.Sprintf("tracee %d exited with return code %d", wpid, ws.ExitStatus())
			handler.HandleTracerLogging(wpid, msg)
			handler.HandleTracerExitedEvent(wpid, ws, rusage)
			if wpid == t.pid {
				return
			} else {
				continue
			}
		}

		// check wait status - WIFSIGNALED
		if ws.Signaled() {
			msg := fmt.Sprintf("tracee %d terminated with signal %d(%s)", wpid, ws.Signal(), ws.Signal())
			handler.HandleTracerLogging(wpid, msg)
			handler.HandleTracerSignaledEvent(wpid, ws, rusage)
			if wpid == t.pid {
				return
			} else {
				continue
			}
		}

		// check wait status - WIFSTOPPED
		if !ws.Stopped() { // cannot happen
			err := fmt.Errorf("unexpected wait status")
			handler.HandleTracerLogging(wpid, err.Error())
			handler.HandleTracerPanicEvent(err)
			return
		}

		// check wait status - WIFSTOPPED
		switch signal := ws.StopSignal(); signal {
		// syscall-stops
		//
		// Using the PTRACE_O_TRACESYSGOOD option is the recommended method
		// to distinguish syscall-stops from other kinds of ptrace-stops.
		case syscall.SIGTRAP | 0x80:
			// reterive tracee info
			if value, ok := t.tracees[wpid]; ok {
				currTracee = value
			} else {
				currTracee = t.addTracee(wpid)
			}

			// reterive syscall info
			curr, err = GetSyscall(wpid)
			if err != nil {
				handler.HandleTracerLogging(wpid, err.Error())
				handler.HandleTracerPanicEvent(err)
				return
			}

			// handle syscall event
			if currTracee.insyscall { // syscall enter event
				// special case
				switch curr.GetNR() {
				case unix.SYS_EXECVE, // an additional notification event of `exec` in child?
					unix.SYS_CLONE: // an additional notification event of `clone` in child?
					if err := curr.GetRetval().Read(); err != nil {
						handler.HandleTracerLogging(wpid, err.Error())
						handler.HandleTracerPanicEvent(err)
						return
					}
					if curr.GetRetval().GetValue() == 0 {
						goto TRACE_CONTINUE
					}
				}

				// inspect
				if continued := handler.HandleTracerSyscallEnterEvent(wpid, curr); continued {
					currTracee.insyscall = false
					currTracee.in = curr
				} else {
					return
				}
			} else { // syscall leave event
				// inspect
				if continued := handler.HandleTracerSyscallLeaveEvent(wpid, curr, currTracee.in); continued {
					currTracee.insyscall = true
					currTracee.in = nil
				} else {
					return
				}
			}

		// PTRACE_EVENT stops
		case syscall.SIGTRAP:
			switch tc := ws.TrapCause(); tc {
			case syscall.PTRACE_EVENT_CLONE, syscall.PTRACE_EVENT_FORK, syscall.PTRACE_EVENT_VFORK:
				if childPid, err := syscall.PtraceGetEventMsg(wpid); err != nil {
					err := fmt.Errorf("PtraceGetEventMsg: %s", err)
					handler.HandleTracerLogging(wpid, err.Error())
					handler.HandleTracerPanicEvent(err)
					return
				} else {
					msg := fmt.Sprintf("tracee %d creates a new child %d", wpid, childPid)
					handler.HandleTracerLogging(wpid, msg)
					handler.HandleTracerNewChildEvent(wpid, int(childPid))
					goto TRACE_CONTINUE
				}
			case syscall.PTRACE_EVENT_EXIT:
				goto TRACE_CONTINUE
			case syscall.PTRACE_TRACEME:
				goto TRACE_CONTINUE
			default:
				msg := fmt.Sprintf("unexpected trap cause %d", tc)
				handler.HandleTracerLogging(wpid, msg)
				goto TRACE_CONTINUE
			}

		// syscall.PTRACE_EVENT_CLONE
		// syscall.PTRACE_EVENT_FORK
		// syscall.PTRACE_EVENT_VFORK
		case syscall.SIGSTOP:
			msg := fmt.Sprintf("tracee %d started with a SIGSTOP", wpid)
			handler.HandleTracerLogging(wpid, msg)

		// ?
		case syscall.SIGCHLD:
			msg := fmt.Sprintf("tracee %d receives child exited signal", wpid)
			handler.HandleTracerLogging(wpid, msg)

		// signal-delivery-stop
		default:
			msg := fmt.Sprintf("unexpected stop signal %d(%s)", signal, signal)
			handler.HandleTracerLogging(wpid, msg)
		}

	TRACE_CONTINUE:
		// Resume tracee execution. Make the kernel stop the child process whenever a
		// system call entry or exit is made.
		if err := syscall.PtraceSyscall(wpid, 0); err != nil {
			err := fmt.Errorf("PtraceSyscall: %s", err)
			handler.HandleTracerLogging(wpid, err.Error())
			handler.HandleTracerPanicEvent(err)
			return
		}
	}
}

func (t *Tracer) addTracee(pid int) *Tracee {
	var tracee = Tracee{insyscall: true}
	t.tracees[pid] = &tracee
	return &tracee
}
