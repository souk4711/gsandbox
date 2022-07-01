package gsandbox

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/souk4711/gsandbox/pkg/ptrace"
)

func (e *Executor) applySyscallFilterWhenEnter(curr *ptrace.Syscall) error {
	var name = curr.GetName()
	e.logger.Info(fmt.Sprintf("syscall: action(enter) func(%s)", name))

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
	var name = curr.GetName()
	e.logger.Info(fmt.Sprintf("syscall: action(exit_) func(%s)", name))

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
