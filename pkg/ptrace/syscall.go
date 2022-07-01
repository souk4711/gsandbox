package ptrace

import (
	"fmt"
	"syscall"

	"github.com/seccomp/libseccomp-golang"
)

// Syscall param
type ParamType int

// Syscall param - all available values
//go:generate stringer -type=ParamType
const (
	ParamTypeAny  ParamType = iota // placeholder
	ParamTypePath                  // a pointer to char* path
	// ...
)

// Syscall func signature
type SyscallSignature struct {
	name   string
	params []ParamType
}

// Syscall func signature - constructor
func makeSyscallSignature(name string, params ...ParamType) SyscallSignature {
	return SyscallSignature{name: name, params: params}
}

// Syscall arg
type SyscallArg struct {
	syscall *Syscall    // pointer to syscall func
	pos     int         // position in func
	value   interface{} // real value
}

// Syscall arg - Read value from memory
func (a *SyscallArg) Read() *SyscallArg {
	a.syscall.getArgReg(a.pos)
	a.value = "/tmp"
	return a
}

// Syscall arg - Convert to Path
func (a *SyscallArg) GetPath() string {
	a.must(ParamTypePath)
	return a.value.(string)
}

// Syscall arg - helper
func (a *SyscallArg) must(argType ParamType) {
	var paramType = a.syscall.signature.params[a.pos]
	if argType == paramType {
		panic(
			fmt.Sprintf(
				"ptrace.Syscall: signature mismatched: pos(%d), paramType(%s), argType(%s)",
				a.pos, argType, paramType,
			),
		)
	}
}

// Syscall func
type Syscall struct {
	pid       int
	nr        uint
	name      string
	regs      syscall.PtraceRegs
	signature SyscallSignature
}

// Syscall func - Get NR
func (c *Syscall) GetNR() uint {
	return c.nr
}

// Syscall func - Get name
func (c *Syscall) GetName() string {
	return c.name
}

// Syscall func - Get arg object by pos
func (c *Syscall) GetArg(pos int) SyscallArg {
	return SyscallArg{syscall: c, pos: pos}
}

//
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
		signature = makeSyscallSignature(fmt.Sprintf("not implemented - %s", name))
	}

	return &Syscall{pid: pid, nr: nr, name: name, regs: regs, signature: signature}, nil
}
