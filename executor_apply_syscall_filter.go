package gsandbox

import (
	"fmt"
	"strings"

	"github.com/souk4711/gsandbox/pkg/ptrace"
	"golang.org/x/sys/unix"
)

func (e *Executor) applySyscallFilterWhenEnter(curr *ptrace.Syscall) (error, error) {
	// prepare data from regs
	for _, arg := range curr.GetArgs() {
		if err := arg.Read(); err != nil {
			return nil, fmt.Errorf("ptrace: %s", err.Error())
		}
	}

	// logging
	var name = curr.GetName()
	var args = make([]string, len(curr.GetArgs()))
	for i, arg := range curr.GetArgs() {
		args[i] = arg.String()
	}
	e.logger.Info(fmt.Sprintf("syscall: Enter: %s(%s)", name, strings.Join(args, ", ")))

	// filter - allowable
	r1, err := e.applySyscallFilterWhenEnter_Allowable(curr)
	if err != nil || r1 != nil {
		return r1, err
	}

	// filter - fs
	r2, err := e.applySyscallFilterWhenEnter_FileAccessControl(curr)
	if err != nil || r2 != nil {
		return r2, err
	}

	// ok
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenEnter_Allowable(curr *ptrace.Syscall) (error, error) {
	if _, ok := e.allowedSyscalls[curr.GetName()]; !ok {
		err := fmt.Errorf("syscall: IllegalCall: func(%s)", curr.GetName())
		return err, nil
	}
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenEnter_FileAccessControl(curr *ptrace.Syscall) (error, error) {
	switch curr.GetNR() {
	case unix.SYS_OPEN:
	case unix.SYS_ACCESS:
	case unix.SYS_OPENAT:
	}

	return nil, nil
}

func (e *Executor) applySyscallFilterWhenExit(curr *ptrace.Syscall, prev *ptrace.Syscall) (error, error) {
	// prepare data from regs
	var retval = curr.GetRetval()
	if err := retval.Read(); err != nil {
		return nil, fmt.Errorf("ptrace: %s", err.Error())
	}

	// logging
	e.logger.Info(fmt.Sprintf("syscall: Exit_:   => %s", retval))

	// filter - fs
	r1, err := e.applySyscallFilterWhenExit_FileAccessControl(curr, prev)
	if err != nil || r1 != nil {
		return err, r1
	}

	// ok
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenExit_FileAccessControl(curr *ptrace.Syscall, prev *ptrace.Syscall) (error, error) {
	switch curr.GetNR() {
	case unix.SYS_OPEN:
	case unix.SYS_ACCESS:
	case unix.SYS_OPENAT:
	}

	return nil, nil
}
