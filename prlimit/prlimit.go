package prlimit

import (
	"syscall"
	"unsafe"
)

var (
	errEAGAIN error = syscall.EAGAIN
	errEINVAL error = syscall.EINVAL
	errENOENT error = syscall.ENOENT
)

func Getprlimit(pid int, resource int, rlim *syscall.Rlimit) error {
	return prlimit(0, resource, nil, rlim)
}

func Setprlimit(pid int, resource int, rlim *syscall.Rlimit) error {
	return prlimit(pid, resource, rlim, nil)
}

func prlimit(pid int, resource int, newlimit *syscall.Rlimit, old *syscall.Rlimit) (err error) {
	_, _, e1 := syscall.RawSyscall6(syscall.SYS_PRLIMIT64, uintptr(pid), uintptr(resource), uintptr(unsafe.Pointer(newlimit)), uintptr(unsafe.Pointer(old)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case syscall.EAGAIN:
		return errEAGAIN
	case syscall.EINVAL:
		return errEINVAL
	case syscall.ENOENT:
		return errENOENT
	}
	return e
}
