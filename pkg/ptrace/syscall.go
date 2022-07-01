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
	Name   string
	Params []ParamType
}

// Syscall func signature - constructor
func makeSyscallSignature(name string, params ...ParamType) SyscallSignature {
	return SyscallSignature{Name: name, Params: params}
}

// Syscall arg
type SyscallArg struct {
	syscall  *Syscall    // pointer to syscall func
	position int         // position in func
	value    interface{} // real value
}

// Syscall arg - Read value from memory
func (a *SyscallArg) Read() *SyscallArg {
	a.syscall.GetReg(a.position)
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
	var paramType = a.syscall.signature.Params[a.position]
	if argType == paramType {
		panic(
			fmt.Sprintf(
				"ptrace.Syscall: signature mismatched: position(%d), paramType(%s), argType(%s)",
				a.position, argType, paramType,
			),
		)
	}
}

// Syscall func
type Syscall struct {
	Pid  int
	Name string

	regs      syscall.PtraceRegs
	signature SyscallSignature
}

// Syscall func - Get arg object by position
func (s *Syscall) GetArg(position int) SyscallArg {
	return SyscallArg{syscall: s, position: position}
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
		signature = makeSyscallSignature(name) // use a default signature
	}

	return &Syscall{
		Pid: pid, Name: name,
		regs: regs, signature: signature,
	}, nil
}
