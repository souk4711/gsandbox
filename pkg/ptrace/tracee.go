package ptrace

type Tracee struct {
	insyscall bool
	in        *Syscall
}
