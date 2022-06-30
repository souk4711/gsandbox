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

func GetPtraceSyscall(pid int) (*PtraceSyscall, error) {
	var regs = syscall.PtraceRegs{}
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return nil, fmt.Errorf("ptrace: %s", err.Error())
	}

	name, err := seccomp.ScmpSyscall(regs.Orig_rax).GetName()
	if err != nil {
		return nil, fmt.Errorf("ptrace: %s", err.Error())
	}

	return &PtraceSyscall{
		Pid: pid, Regs: regs, Name: name,
	}, nil
}
