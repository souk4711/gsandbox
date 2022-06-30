package ptrace

import (
	"fmt"
	"syscall"

	"github.com/seccomp/libseccomp-golang"
)

type Syscall struct {
	Pid  int
	Name string

	regs      syscall.PtraceRegs
	signature SyscallSignature
}

func GetSyscall(pid int) (*Syscall, error) {
	var regs = syscall.PtraceRegs{}
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return nil, fmt.Errorf("ptrace: %s", err.Error())
	}

	var nr = uint(regs.Orig_rax)
	var name, err = seccomp.ScmpSyscall(nr).GetName()
	if err != nil {
		return nil, fmt.Errorf("ptrace: %s", err.Error())
	}

	var signature SyscallSignature
	if sig, ok := syscallTable[nr]; ok {
		signature = sig
	} else {
		signature = makeSyscallSignature(name)
	}

	return &Syscall{
		Pid: pid, Name: name, regs: regs, signature: signature,
	}, nil
}
