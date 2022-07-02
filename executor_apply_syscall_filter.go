package gsandbox

import (
	"fmt"
	"strings"

	"github.com/souk4711/gsandbox/pkg/ptrace"
	"golang.org/x/sys/unix"
)

func (e *Executor) applySyscallFilterWhenEnter(curr *ptrace.Syscall) error {
	// prepare data from regs
	for _, arg := range curr.GetArgs() {
		if err := arg.Read(); err != nil {
			return fmt.Errorf("syscall: %s", err.Error())
		}
	}

	// logging
	var name = curr.GetName()
	var args = make([]string, len(curr.GetArgs()))
	for i, arg := range curr.GetArgs() {
		args[i] = arg.String()
	}
	e.logger.Info(fmt.Sprintf("syscall: Enter: %s(%s)", name, strings.Join(args, ", ")))

	// filter
	if err := e.applySyscallFilterWhenEnter_Allowable(curr); err != nil {
		return err
	}
	if err := e.applySyscallFilterWhenEnter_FileAccessControl(curr); err != nil {
		return err
	}
	return nil
}

func (e *Executor) applySyscallFilterWhenEnter_Allowable(curr *ptrace.Syscall) error {
	if _, ok := e.allowedSyscalls[curr.GetName()]; !ok {
		err := fmt.Errorf("syscall: IllegalCall: func(%s)", curr.GetName())
		return err
	}
	return nil
}

func (e *Executor) applySyscallFilterWhenEnter_FileAccessControl(curr *ptrace.Syscall) error {
	switch curr.GetNR() {
	case unix.SYS_OPEN:
	case unix.SYS_ACCESS:
	case unix.SYS_OPENAT:
	}

	return nil
}

func (e *Executor) applySyscallFilterWhenExit(curr *ptrace.Syscall, prev *ptrace.Syscall) error {
	// prepare data from regs
	var retval = curr.GetRetval()
	if err := retval.Read(); err != nil {
		return fmt.Errorf("syscall: %s", err.Error())
	}

	// logging
	e.logger.Info(fmt.Sprintf("syscall: Exit_:   => %s", retval))

	// filter
	if err := e.applySyscallFilterWhenExit_FileAccessControl(curr, prev); err != nil {
		return err
	}
	return nil
}

func (e *Executor) applySyscallFilterWhenExit_FileAccessControl(curr *ptrace.Syscall, prev *ptrace.Syscall) error {
	switch curr.GetNR() {
	case unix.SYS_OPEN:
	case unix.SYS_ACCESS:
	case unix.SYS_OPENAT:
	}

	return nil
}
