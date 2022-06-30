package ptrace

import (
	"fmt"
	"syscall"

	"github.com/seccomp/libseccomp-golang"
)

type PtraceSyscall struct {
	Pid int

	Regs syscall.PtraceRegs
	Name string
}

func (p *PtraceSyscall) Load() error {
	err := syscall.PtraceGetRegs(p.Pid, &p.Regs)
	if err != nil {
		return fmt.Errorf("ptrace: %s", err.Error())
	}

	name, err := seccomp.ScmpSyscall(p.Regs.Orig_rax).GetName()
	if err != nil {
		return fmt.Errorf("ptrace: %s", err.Error())
	}

	p.Name = name
	return nil
}
