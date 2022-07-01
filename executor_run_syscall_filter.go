package gsandbox

import (
	"fmt"

	"github.com/souk4711/gsandbox/pkg/ptrace"
)

func (e *Executor) runSyscallFilter(ptraceSyscall *ptrace.Syscall) error {
	if err := e.runSyscallFilter_Allowable(ptraceSyscall); err != nil {
		return err
	}
	if err := e.runSyscallFilter_FileAccessControl(ptraceSyscall); err != nil {
		return err
	}
	return nil
}

func (e *Executor) runSyscallFilter_Allowable(ptraceSyscall *ptrace.Syscall) error {
	var name = ptraceSyscall.GetName()
	e.logger.Info(fmt.Sprintf("syscall: func(%s)", name))

	if _, ok := e.allowedSyscalls[name]; !ok {
		err := fmt.Errorf("syscall: Deny: func(%s)", name)
		return err
	}
	return nil
}

func (e *Executor) runSyscallFilter_FileAccessControl(ptraceSyscall *ptrace.Syscall) error {
	return nil
}
