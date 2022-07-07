package ptrace

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func Trace(pid int, handler TracerHandler) {
	var tracer = Tracer{pid: pid, tracees: make(map[int]*Tracee)}
	tracer.trace(handler)
}

type TracerHandler interface {
	HandleTracerPanicEvent(err error)                                                     // panic
	HandleTracerExitedEvent(ws syscall.WaitStatus, rusage syscall.Rusage)                 // ws.Exited()
	HandleTracerSignaledEvent(ws syscall.WaitStatus, rusage syscall.Rusage)               // ws.Signaled()
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
	flag = flag | syscall.PTRACE_O_TRACEEXIT    // stop the tracee at exit
	flag = flag | syscall.PTRACE_O_TRACECLONE   // automatically trace clone(2) children
	flag = flag | syscall.PTRACE_O_TRACEFORK    // automatically trace fork(2) children
	flag = flag | syscall.PTRACE_O_TRACEVFORK   // automatically trace vfork(2) children
	if err := syscall.PtraceSetOptions(t.pid, flag); err != nil {
		handler.HandleTracerPanicEvent(err)
		return
	}

	var ws syscall.WaitStatus
	var rusage syscall.Rusage
	var currTracee *Tracee
	for {
		wpid, err := syscall.Wait4(-t.pid, &ws, syscall.WALL, &rusage)
		if err != nil {
			handler.HandleTracerPanicEvent(err)
			return
		}

		// reterive tracee info
		if value, ok := t.tracees[wpid]; ok {
			currTracee = value
		} else {
			currTracee = t.addTracee(wpid)
		}

		// check wait status
		if wpid == t.pid {
			if ws.Exited() {
				handler.HandleTracerExitedEvent(ws, rusage)
				return
			} else if ws.Signaled() {
				handler.HandleTracerSignaledEvent(ws, rusage)
				return
			} else if ws.Stopped() {
				_ = ws.Signal()
			}
		}

		// reterive syscall info
		curr, err := GetSyscall(wpid)
		if err != nil {
			handler.HandleTracerPanicEvent(err)
			return
		}

		// handle syscall event
		if currTracee.insyscall { // syscall enter event
			// special case
			switch curr.GetNR() {
			case unix.SYS_EXECVE, unix.SYS_EXECVEAT: // an additional notification event of `exec`?
				if err := curr.GetRetval().Read(); err != nil {
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

	TRACE_CONTINUE:
		// Resume tracee execution. Make the kernel stop the child process whenever a
		// system call entry or exit is made.
		if err := syscall.PtraceSyscall(wpid, 0); err != nil {
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
