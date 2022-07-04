package ptrace

import (
	"fmt"
	"syscall"

	"github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// Syscall param
type ParamType int

// Syscall param - all available values
//go:generate stringer -type=ParamType -output=syscall_paramtype_string.go
const (
	ParamTypeAny      ParamType = iota // placeholder
	ParamTypePath                      // a pointer to char* path
	ParamTypeFd                        // int fd
	ParamTypeFlagOpen                  // flag for open
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
	syscall *Syscall // pointer to syscall func
	pos     int      // position in func

	// hold ANY value, available after a call to #Read
	v_int int
	v_str string
}

// Syscall func - interface Stringer
func (a *SyscallArg) String() string {
	var paramType = a.syscall.signature.params[a.pos]
	switch paramType {
	case ParamTypePath:
		return fmt.Sprintf("'%s'", a.GetPath())
	case ParamTypeFd:
		return fmt.Sprint(Fd(a.GetFd()))
	case ParamTypeFlagOpen:
		return fmt.Sprint(FlagOpen(a.GetFlag()))
	default:
		return "<any>"
	}
}

// Syscall arg - read value from register
func (a *SyscallArg) Read() error {
	var paramType = a.syscall.signature.params[a.pos]
	var regptr = a.syscall.getArgReg(a.pos)

	switch paramType {
	case ParamTypePath:
		v, err := a.readString(regptr, unix.PathMax)
		if err != nil {
			return err
		}
		a.v_str = v
	case ParamTypeFd:
		a.v_int = int(int32(regptr))
	case ParamTypeFlagOpen:
		a.v_int = int(int32(regptr))
	}

	return nil
}

// Syscall arg - convert value to Path
func (a *SyscallArg) GetPath() string {
	return a.v_str
}

// Syscall arg - convert value to Fd
func (a *SyscallArg) GetFd() int {
	return a.v_int
}

// Syscall arg - convert value to Flag
func (a *SyscallArg) GetFlag() int {
	return a.v_int
}

// Syscall arg - check param type
func (a *SyscallArg) IsParamType(t ParamType) bool {
	return a.syscall.signature.params[a.pos] == t
}

// Syscall arg - helper for read null-terminated string
func (a *SyscallArg) readString(addr uintptr, max int) (string, error) {
	if addr == 0 {
		return "<nil>", nil
	}

	var str string
	var buf [1]byte
	for len(str) < max {
		if _, err := syscall.PtracePeekData(a.syscall.pid, addr, buf[:]); err != nil {
			return "", fmt.Errorf("PeekData: %s", err.Error())
		}
		if buf[0] == 0 { // NULL
			break
		}
		str = str + string(buf[:])
		addr++
	}
	return str, nil
}

// Syscall retval
type SyscallRetval struct {
	syscall *Syscall      // pointer to syscall func
	value   int           // hold value, available after a call to #Read
	errno   syscall.Errno // errno, available after a call to #Read
}

// Syscall retval - interface Stringer
func (r *SyscallRetval) String() string {
	if r.HasError() {
		return fmt.Sprintf("%d, %s", r.value, r.errno.Error())
	} else {
		return fmt.Sprint(r.value)
	}
}

// Syscall retval - read value from register
func (r *SyscallRetval) Read() error {
	if r.value = r.syscall.getRetval(); r.value < 0 {
		r.errno = syscall.Errno(-r.value)
	}
	return nil
}

// Syscall retval - attr reader for value
func (r *SyscallRetval) GetValue() int {
	return r.value
}

// Syscall retval - attr reader for errno
func (r *SyscallRetval) GetErrno() syscall.Errno {
	return r.errno
}

// Syscall retval - check errno
func (r *SyscallRetval) HasError() bool {
	return r.value < 0
}

// Syscall func
type Syscall struct {
	pid       int                // process id
	regs      syscall.PtraceRegs // registers
	nr        uint               // number
	name      string             // name
	signature SyscallSignature   // signature
	args      []*SyscallArg      // arguments
	retval    *SyscallRetval     // return value
}

// Syscall func - attr reader for nr
func (c *Syscall) GetNR() uint {
	return c.nr
}

// Syscall func - attr reader for name
func (c *Syscall) GetName() string {
	return c.name
}

// Syscall func - attr reader for args
func (c *Syscall) GetArgs() []*SyscallArg {
	return c.args
}

// Syscall func - attr reader for arg in specified postion
func (c *Syscall) GetArg(pos int) *SyscallArg {
	return c.args[pos]
}

// Syscall func - attr reader for retval
func (c *Syscall) GetRetval() *SyscallRetval {
	return c.retval
}

//
func GetSyscall(pid int) (*Syscall, error) {
	var regs = syscall.PtraceRegs{}
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return nil, fmt.Errorf("GetRegs: %s", err.Error())
	}

	var nr = uint(regs.Orig_rax)
	var name, err = seccomp.ScmpSyscall(nr).GetName()
	if err != nil {
		return nil, fmt.Errorf("ScmpGetName: %s", err.Error())
	}

	var signature SyscallSignature
	if sig, ok := syscallTable[nr]; ok {
		signature = sig
	} else {
		signature = makeSyscallSignature(fmt.Sprintf("signature(%s) not implemented", name))
	}

	var call = Syscall{pid: pid, regs: regs, nr: nr, name: name, signature: signature}
	var args = make([]*SyscallArg, len(signature.params))
	for i := range signature.params {
		args[i] = &SyscallArg{syscall: &call, pos: i}
	}
	call.args = args
	call.retval = &SyscallRetval{syscall: &call}

	return &call, nil
}
