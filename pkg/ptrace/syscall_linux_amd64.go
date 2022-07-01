package ptrace

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Calling Conventions. Plz see https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#Calling-Conventions
func (c *Syscall) getArgReg(pos int) uint {
	switch pos {
	case 0:
		return uint(c.regs.Rdi)
	case 1:
		return uint(c.regs.Rsi)
	case 2:
		return uint(c.regs.Rdx)
	case 3:
		return uint(c.regs.R10)
	case 4:
		return uint(c.regs.R8)
	case 5:
		return uint(c.regs.R9)
	default:
		panic(
			fmt.Sprintf("index out of range [%d] with length 6", pos),
		)
	}
}

// Linux-4.14.0 System Call Table. Plz see https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#tables
var syscallTable = map[uint]SyscallSignature{
	unix.SYS_READ:                   makeSyscallSignature("read", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_WRITE:                  makeSyscallSignature("write", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_OPEN:                   makeSyscallSignature("open", ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_CLOSE:                  makeSyscallSignature("close", ParamTypeAny),
	unix.SYS_STAT:                   makeSyscallSignature("stat", ParamTypePath, ParamTypeAny),
	unix.SYS_FSTAT:                  makeSyscallSignature("fstat", ParamTypeAny, ParamTypeAny),
	unix.SYS_LSTAT:                  makeSyscallSignature("lstat", ParamTypePath, ParamTypeAny),
	unix.SYS_POLL:                   makeSyscallSignature("poll", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_LSEEK:                  makeSyscallSignature("lseek", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MMAP:                   makeSyscallSignature("mmap", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MPROTECT:               makeSyscallSignature("mprotect", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MUNMAP:                 makeSyscallSignature("munmap", ParamTypeAny, ParamTypeAny),
	unix.SYS_BRK:                    makeSyscallSignature("brk", ParamTypeAny),
	unix.SYS_RT_SIGACTION:           makeSyscallSignature("rt_sigaction", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RT_SIGPROCMASK:         makeSyscallSignature("rt_sigprocmask", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RT_SIGRETURN:           makeSyscallSignature("rt_sigreturn"),
	unix.SYS_IOCTL:                  makeSyscallSignature("ioctl", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PREAD64:                makeSyscallSignature("pread64", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PWRITE64:               makeSyscallSignature("pwrite64", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_READV:                  makeSyscallSignature("readv", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_WRITEV:                 makeSyscallSignature("writev", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_ACCESS:                 makeSyscallSignature("access", ParamTypePath, ParamTypeAny),
	unix.SYS_PIPE:                   makeSyscallSignature("pipe", ParamTypeAny),
	unix.SYS_SELECT:                 makeSyscallSignature("select", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_YIELD:            makeSyscallSignature("sched_yield"),
	unix.SYS_MREMAP:                 makeSyscallSignature("mremap", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MSYNC:                  makeSyscallSignature("msync", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MINCORE:                makeSyscallSignature("mincore", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MADVISE:                makeSyscallSignature("madvise", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SHMGET:                 makeSyscallSignature("shmget", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SHMAT:                  makeSyscallSignature("shmat", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SHMCTL:                 makeSyscallSignature("shmctl", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_DUP:                    makeSyscallSignature("dup", ParamTypeAny),
	unix.SYS_DUP2:                   makeSyscallSignature("dup2", ParamTypeAny, ParamTypeAny),
	unix.SYS_PAUSE:                  makeSyscallSignature("pause"),
	unix.SYS_NANOSLEEP:              makeSyscallSignature("nanosleep", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETITIMER:              makeSyscallSignature("getitimer", ParamTypeAny, ParamTypeAny),
	unix.SYS_ALARM:                  makeSyscallSignature("alarm", ParamTypeAny),
	unix.SYS_SETITIMER:              makeSyscallSignature("setitimer", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETPID:                 makeSyscallSignature("getpid"),
	unix.SYS_SENDFILE:               makeSyscallSignature("sendfile", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SOCKET:                 makeSyscallSignature("socket", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_CONNECT:                makeSyscallSignature("connect", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_ACCEPT:                 makeSyscallSignature("accept", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SENDTO:                 makeSyscallSignature("sendto", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RECVFROM:               makeSyscallSignature("recvfrom", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SENDMSG:                makeSyscallSignature("sendmsg", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RECVMSG:                makeSyscallSignature("recvmsg", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SHUTDOWN:               makeSyscallSignature("shutdown", ParamTypeAny, ParamTypeAny),
	unix.SYS_BIND:                   makeSyscallSignature("bind", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_LISTEN:                 makeSyscallSignature("listen", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETSOCKNAME:            makeSyscallSignature("getsockname", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETPEERNAME:            makeSyscallSignature("getpeername", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SOCKETPAIR:             makeSyscallSignature("socketpair", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SETSOCKOPT:             makeSyscallSignature("setsockopt", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETSOCKOPT:             makeSyscallSignature("getsockopt", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_CLONE:                  makeSyscallSignature("clone", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FORK:                   makeSyscallSignature("fork"),
	unix.SYS_VFORK:                  makeSyscallSignature("vfork"),
	unix.SYS_EXECVE:                 makeSyscallSignature("execve", ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_EXIT:                   makeSyscallSignature("exit", ParamTypeAny),
	unix.SYS_WAIT4:                  makeSyscallSignature("wait4", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_KILL:                   makeSyscallSignature("kill", ParamTypeAny, ParamTypeAny),
	unix.SYS_UNAME:                  makeSyscallSignature("uname", ParamTypeAny),
	unix.SYS_SEMGET:                 makeSyscallSignature("semget", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SEMOP:                  makeSyscallSignature("semop", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SEMCTL:                 makeSyscallSignature("semctl", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SHMDT:                  makeSyscallSignature("shmdt", ParamTypeAny),
	unix.SYS_MSGGET:                 makeSyscallSignature("msgget", ParamTypeAny, ParamTypeAny),
	unix.SYS_MSGSND:                 makeSyscallSignature("msgsnd", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MSGRCV:                 makeSyscallSignature("msgrcv", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MSGCTL:                 makeSyscallSignature("msgctl", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FCNTL:                  makeSyscallSignature("fcntl", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FLOCK:                  makeSyscallSignature("flock", ParamTypeAny, ParamTypeAny),
	unix.SYS_FSYNC:                  makeSyscallSignature("fsync", ParamTypeAny),
	unix.SYS_FDATASYNC:              makeSyscallSignature("fdatasync", ParamTypeAny),
	unix.SYS_TRUNCATE:               makeSyscallSignature("truncate", ParamTypePath, ParamTypeAny),
	unix.SYS_FTRUNCATE:              makeSyscallSignature("ftruncate", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETDENTS:               makeSyscallSignature("getdents", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETCWD:                 makeSyscallSignature("getcwd", ParamTypePath, ParamTypeAny),
	unix.SYS_CHDIR:                  makeSyscallSignature("chdir", ParamTypePath),
	unix.SYS_FCHDIR:                 makeSyscallSignature("fchdir", ParamTypeAny),
	unix.SYS_RENAME:                 makeSyscallSignature("rename", ParamTypePath, ParamTypePath),
	unix.SYS_MKDIR:                  makeSyscallSignature("mkdir", ParamTypePath, ParamTypeAny),
	unix.SYS_RMDIR:                  makeSyscallSignature("rmdir", ParamTypePath),
	unix.SYS_CREAT:                  makeSyscallSignature("creat", ParamTypePath, ParamTypeAny),
	unix.SYS_LINK:                   makeSyscallSignature("link", ParamTypePath, ParamTypePath),
	unix.SYS_UNLINK:                 makeSyscallSignature("unlink", ParamTypePath),
	unix.SYS_SYMLINK:                makeSyscallSignature("symlink", ParamTypePath, ParamTypePath),
	unix.SYS_READLINK:               makeSyscallSignature("readlink", ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_CHMOD:                  makeSyscallSignature("chmod", ParamTypePath, ParamTypeAny),
	unix.SYS_FCHMOD:                 makeSyscallSignature("fchmod", ParamTypeAny, ParamTypeAny),
	unix.SYS_CHOWN:                  makeSyscallSignature("chown", ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_FCHOWN:                 makeSyscallSignature("fchown", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_LCHOWN:                 makeSyscallSignature("lchown", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_UMASK:                  makeSyscallSignature("umask", ParamTypeAny),
	unix.SYS_GETTIMEOFDAY:           makeSyscallSignature("gettimeofday", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETRLIMIT:              makeSyscallSignature("getrlimit", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETRUSAGE:              makeSyscallSignature("getrusage", ParamTypeAny, ParamTypeAny),
	unix.SYS_SYSINFO:                makeSyscallSignature("sysinfo", ParamTypeAny),
	unix.SYS_TIMES:                  makeSyscallSignature("times", ParamTypeAny),
	unix.SYS_PTRACE:                 makeSyscallSignature("ptrace", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETUID:                 makeSyscallSignature("getuid"),
	unix.SYS_SYSLOG:                 makeSyscallSignature("syslog", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETGID:                 makeSyscallSignature("getgid"),
	unix.SYS_SETUID:                 makeSyscallSignature("setuid", ParamTypeAny),
	unix.SYS_SETGID:                 makeSyscallSignature("setgid", ParamTypeAny),
	unix.SYS_GETEUID:                makeSyscallSignature("geteuid"),
	unix.SYS_GETEGID:                makeSyscallSignature("getegid"),
	unix.SYS_SETPGID:                makeSyscallSignature("setpgid", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETPPID:                makeSyscallSignature("getppid"),
	unix.SYS_GETPGRP:                makeSyscallSignature("getpgrp"),
	unix.SYS_SETSID:                 makeSyscallSignature("setsid"),
	unix.SYS_SETREUID:               makeSyscallSignature("setreuid", ParamTypeAny, ParamTypeAny),
	unix.SYS_SETREGID:               makeSyscallSignature("setregid", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETGROUPS:              makeSyscallSignature("getgroups", ParamTypeAny, ParamTypeAny),
	unix.SYS_SETGROUPS:              makeSyscallSignature("setgroups", ParamTypeAny, ParamTypeAny),
	unix.SYS_SETRESUID:              makeSyscallSignature("setresuid", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETRESUID:              makeSyscallSignature("getresuid", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SETRESGID:              makeSyscallSignature("setresgid", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETRESGID:              makeSyscallSignature("getresgid", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETPGID:                makeSyscallSignature("getpgid", ParamTypeAny),
	unix.SYS_SETFSUID:               makeSyscallSignature("setfsuid", ParamTypeAny),
	unix.SYS_SETFSGID:               makeSyscallSignature("setfsgid", ParamTypeAny),
	unix.SYS_GETSID:                 makeSyscallSignature("getsid", ParamTypeAny),
	unix.SYS_CAPGET:                 makeSyscallSignature("capget", ParamTypeAny, ParamTypeAny),
	unix.SYS_CAPSET:                 makeSyscallSignature("capset", ParamTypeAny, ParamTypeAny),
	unix.SYS_RT_SIGPENDING:          makeSyscallSignature("rt_sigpending", ParamTypeAny),
	unix.SYS_RT_SIGTIMEDWAIT:        makeSyscallSignature("rt_sigtimedwait", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RT_SIGQUEUEINFO:        makeSyscallSignature("rt_sigqueueinfo", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RT_SIGSUSPEND:          makeSyscallSignature("rt_sigsuspend", ParamTypeAny),
	unix.SYS_SIGALTSTACK:            makeSyscallSignature("sigaltstack", ParamTypeAny, ParamTypeAny),
	unix.SYS_UTIME:                  makeSyscallSignature("utime", ParamTypePath, ParamTypeAny),
	unix.SYS_MKNOD:                  makeSyscallSignature("mknod", ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_USELIB:                 makeSyscallSignature("uselib", ParamTypeAny),
	unix.SYS_PERSONALITY:            makeSyscallSignature("personality", ParamTypeAny),
	unix.SYS_USTAT:                  makeSyscallSignature("ustat", ParamTypeAny, ParamTypeAny),
	unix.SYS_STATFS:                 makeSyscallSignature("statfs", ParamTypePath, ParamTypeAny),
	unix.SYS_FSTATFS:                makeSyscallSignature("fstatfs", ParamTypeAny, ParamTypeAny),
	unix.SYS_SYSFS:                  makeSyscallSignature("sysfs", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETPRIORITY:            makeSyscallSignature("getpriority", ParamTypeAny, ParamTypeAny),
	unix.SYS_SETPRIORITY:            makeSyscallSignature("setpriority", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_SETPARAM:         makeSyscallSignature("sched_setparam", ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_GETPARAM:         makeSyscallSignature("sched_getparam", ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_SETSCHEDULER:     makeSyscallSignature("sched_setscheduler", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_GETSCHEDULER:     makeSyscallSignature("sched_getscheduler", ParamTypeAny),
	unix.SYS_SCHED_GET_PRIORITY_MAX: makeSyscallSignature("sched_get_priority_max", ParamTypeAny),
	unix.SYS_SCHED_GET_PRIORITY_MIN: makeSyscallSignature("sched_get_priority_min", ParamTypeAny),
	unix.SYS_SCHED_RR_GET_INTERVAL:  makeSyscallSignature("sched_rr_get_interval", ParamTypeAny, ParamTypeAny),
	unix.SYS_MLOCK:                  makeSyscallSignature("mlock", ParamTypeAny, ParamTypeAny),
	unix.SYS_MUNLOCK:                makeSyscallSignature("munlock", ParamTypeAny, ParamTypeAny),
	unix.SYS_MLOCKALL:               makeSyscallSignature("mlockall", ParamTypeAny),
	unix.SYS_MUNLOCKALL:             makeSyscallSignature("munlockall"),
	unix.SYS_VHANGUP:                makeSyscallSignature("vhangup"),
	unix.SYS_MODIFY_LDT:             makeSyscallSignature("modify_ldt", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PIVOT_ROOT:             makeSyscallSignature("pivot_root", ParamTypeAny, ParamTypeAny),
	unix.SYS__SYSCTL:                makeSyscallSignature("_sysctl", ParamTypeAny),
	unix.SYS_PRCTL:                  makeSyscallSignature("prctl", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_ARCH_PRCTL:             makeSyscallSignature("arch_prctl", ParamTypeAny, ParamTypeAny),
	unix.SYS_ADJTIMEX:               makeSyscallSignature("adjtimex", ParamTypeAny),
	unix.SYS_SETRLIMIT:              makeSyscallSignature("setrlimit", ParamTypeAny, ParamTypeAny),
	unix.SYS_CHROOT:                 makeSyscallSignature("chroot", ParamTypePath),
	unix.SYS_SYNC:                   makeSyscallSignature("sync"),
	unix.SYS_ACCT:                   makeSyscallSignature("acct", ParamTypeAny),
	unix.SYS_SETTIMEOFDAY:           makeSyscallSignature("settimeofday", ParamTypeAny, ParamTypeAny),
	unix.SYS_MOUNT:                  makeSyscallSignature("mount", ParamTypePath, ParamTypePath, ParamTypePath, ParamTypeAny, ParamTypePath),
	unix.SYS_UMOUNT2:                makeSyscallSignature("umount2", ParamTypePath, ParamTypeAny),
	unix.SYS_SWAPON:                 makeSyscallSignature("swapon", ParamTypeAny, ParamTypeAny),
	unix.SYS_SWAPOFF:                makeSyscallSignature("swapoff", ParamTypeAny),
	unix.SYS_REBOOT:                 makeSyscallSignature("reboot", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SETHOSTNAME:            makeSyscallSignature("sethostname", ParamTypeAny, ParamTypeAny),
	unix.SYS_SETDOMAINNAME:          makeSyscallSignature("setdomainname", ParamTypeAny, ParamTypeAny),
	unix.SYS_IOPL:                   makeSyscallSignature("iopl", ParamTypeAny),
	unix.SYS_IOPERM:                 makeSyscallSignature("ioperm", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_CREATE_MODULE:          makeSyscallSignature("create_module", ParamTypePath, ParamTypeAny),
	unix.SYS_INIT_MODULE:            makeSyscallSignature("init_module", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_DELETE_MODULE:          makeSyscallSignature("delete_module", ParamTypeAny, ParamTypeAny),
	unix.SYS_GET_KERNEL_SYMS:        makeSyscallSignature("get_kernel_syms", ParamTypeAny),
	// unix.SYS_QUERY_MODULE:query_module (only present in Linux < 2.6)
	unix.SYS_QUOTACTL:   makeSyscallSignature("quotactl", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_NFSSERVCTL: makeSyscallSignature("nfsservctl", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	// unix.SYS_GETPMSG:getpmsg (not implemented in the Linux kernel)
	// unix.SYS_PUTPMSG:putpmsg (not implemented in the Linux kernel)
	// unix.SYSCALL:afs_syscall (not implemented in the Linux kernel)
	// unix.SYS_TUXCALL:tuxcall (not implemented in the Linux kernel)
	// unix.SYS_SECURITY:security (not implemented in the Linux kernel)
	unix.SYS_GETTID:            makeSyscallSignature("gettid"),
	unix.SYS_READAHEAD:         makeSyscallSignature("readahead", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SETXATTR:          makeSyscallSignature("setxattr", ParamTypePath, ParamTypePath, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_LSETXATTR:         makeSyscallSignature("lsetxattr", ParamTypePath, ParamTypePath, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FSETXATTR:         makeSyscallSignature("fsetxattr", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETXATTR:          makeSyscallSignature("getxattr", ParamTypePath, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_LGETXATTR:         makeSyscallSignature("lgetxattr", ParamTypePath, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_FGETXATTR:         makeSyscallSignature("fgetxattr", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_LISTXATTR:         makeSyscallSignature("listxattr", ParamTypePath, ParamTypePath, ParamTypeAny),
	unix.SYS_LLISTXATTR:        makeSyscallSignature("llistxattr", ParamTypePath, ParamTypePath, ParamTypeAny),
	unix.SYS_FLISTXATTR:        makeSyscallSignature("flistxattr", ParamTypeAny, ParamTypePath, ParamTypeAny),
	unix.SYS_REMOVEXATTR:       makeSyscallSignature("removexattr", ParamTypePath, ParamTypePath),
	unix.SYS_LREMOVEXATTR:      makeSyscallSignature("lremovexattr", ParamTypePath, ParamTypePath),
	unix.SYS_FREMOVEXATTR:      makeSyscallSignature("fremovexattr", ParamTypeAny, ParamTypePath),
	unix.SYS_TKILL:             makeSyscallSignature("tkill", ParamTypeAny, ParamTypeAny),
	unix.SYS_TIME:              makeSyscallSignature("time", ParamTypeAny),
	unix.SYS_FUTEX:             makeSyscallSignature("futex", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_SETAFFINITY: makeSyscallSignature("sched_setaffinity", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_GETAFFINITY: makeSyscallSignature("sched_getaffinity", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SET_THREAD_AREA:   makeSyscallSignature("set_thread_area", ParamTypeAny),
	unix.SYS_IO_SETUP:          makeSyscallSignature("io_setup", ParamTypeAny, ParamTypeAny),
	unix.SYS_IO_DESTROY:        makeSyscallSignature("io_destroy", ParamTypeAny),
	unix.SYS_IO_GETEVENTS:      makeSyscallSignature("io_getevents", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_IO_SUBMIT:         makeSyscallSignature("io_submit", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_IO_CANCEL:         makeSyscallSignature("io_cancel", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GET_THREAD_AREA:   makeSyscallSignature("get_thread_area", ParamTypeAny),
	unix.SYS_LOOKUP_DCOOKIE:    makeSyscallSignature("lookup_dcookie", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_EPOLL_CREATE:      makeSyscallSignature("epoll_create", ParamTypeAny),
	// unix.SYS_EPOLL_CTL_OLD:epoll_ctl_old (not implemented in the Linux kernel)
	// unix.SYS_EPOLL_WAIT_OLD:epoll_wait_old (not implemented in the Linux kernel)
	unix.SYS_REMAP_FILE_PAGES: makeSyscallSignature("remap_file_pages", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETDENTS64:       makeSyscallSignature("getdents64", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SET_TID_ADDRESS:  makeSyscallSignature("set_tid_address", ParamTypeAny),
	unix.SYS_RESTART_SYSCALL:  makeSyscallSignature("restart_syscall"),
	unix.SYS_SEMTIMEDOP:       makeSyscallSignature("semtimedop", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FADVISE64:        makeSyscallSignature("fadvise64", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TIMER_CREATE:     makeSyscallSignature("timer_create", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TIMER_SETTIME:    makeSyscallSignature("timer_settime", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TIMER_GETTIME:    makeSyscallSignature("timer_gettime", ParamTypeAny, ParamTypeAny),
	unix.SYS_TIMER_GETOVERRUN: makeSyscallSignature("timer_getoverrun", ParamTypeAny),
	unix.SYS_TIMER_DELETE:     makeSyscallSignature("timer_delete", ParamTypeAny),
	unix.SYS_CLOCK_SETTIME:    makeSyscallSignature("clock_settime", ParamTypeAny, ParamTypeAny),
	unix.SYS_CLOCK_GETTIME:    makeSyscallSignature("clock_gettime", ParamTypeAny, ParamTypeAny),
	unix.SYS_CLOCK_GETRES:     makeSyscallSignature("clock_getres", ParamTypeAny, ParamTypeAny),
	unix.SYS_CLOCK_NANOSLEEP:  makeSyscallSignature("clock_nanosleep", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_EXIT_GROUP:       makeSyscallSignature("exit_group", ParamTypeAny),
	unix.SYS_EPOLL_WAIT:       makeSyscallSignature("epoll_wait", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_EPOLL_CTL:        makeSyscallSignature("epoll_ctl", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TGKILL:           makeSyscallSignature("tgkill", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_UTIMES:           makeSyscallSignature("utimes", ParamTypePath, ParamTypeAny),
	// unix.SYS_VSERVER:vserver (not implemented in the Linux kernel)
	unix.SYS_MBIND:             makeSyscallSignature("mbind", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SET_MEMPOLICY:     makeSyscallSignature("set_mempolicy", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GET_MEMPOLICY:     makeSyscallSignature("get_mempolicy", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MQ_OPEN:           makeSyscallSignature("mq_open", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MQ_UNLINK:         makeSyscallSignature("mq_unlink", ParamTypeAny),
	unix.SYS_MQ_TIMEDSEND:      makeSyscallSignature("mq_timedsend", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MQ_TIMEDRECEIVE:   makeSyscallSignature("mq_timedreceive", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MQ_NOTIFY:         makeSyscallSignature("mq_notify", ParamTypeAny, ParamTypeAny),
	unix.SYS_MQ_GETSETATTR:     makeSyscallSignature("mq_getsetattr", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_KEXEC_LOAD:        makeSyscallSignature("kexec_load", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_WAITID:            makeSyscallSignature("waitid", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_ADD_KEY:           makeSyscallSignature("add_key", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_REQUEST_KEY:       makeSyscallSignature("request_key", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_KEYCTL:            makeSyscallSignature("keyctl", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_IOPRIO_SET:        makeSyscallSignature("ioprio_set", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_IOPRIO_GET:        makeSyscallSignature("ioprio_get", ParamTypeAny, ParamTypeAny),
	unix.SYS_INOTIFY_INIT:      makeSyscallSignature("inotify_init"),
	unix.SYS_INOTIFY_ADD_WATCH: makeSyscallSignature("inotify_add_watch", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_INOTIFY_RM_WATCH:  makeSyscallSignature("inotify_rm_watch", ParamTypeAny, ParamTypeAny),
	unix.SYS_MIGRATE_PAGES:     makeSyscallSignature("migrate_pages", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_OPENAT:            makeSyscallSignature("openat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_MKDIRAT:           makeSyscallSignature("mkdirat", ParamTypeAny, ParamTypePath, ParamTypeAny),
	unix.SYS_MKNODAT:           makeSyscallSignature("mknodat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_FCHOWNAT:          makeSyscallSignature("fchownat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FUTIMESAT:         makeSyscallSignature("futimesat", ParamTypeAny, ParamTypePath, ParamTypeAny),
	unix.SYS_NEWFSTATAT:        makeSyscallSignature("newfstatat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_UNLINKAT:          makeSyscallSignature("unlinkat", ParamTypeAny, ParamTypePath, ParamTypeAny),
	unix.SYS_RENAMEAT:          makeSyscallSignature("renameat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypePath),
	unix.SYS_LINKAT:            makeSyscallSignature("linkat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypePath, ParamTypeAny),
	unix.SYS_SYMLINKAT:         makeSyscallSignature("symlinkat", ParamTypePath, ParamTypeAny, ParamTypePath),
	unix.SYS_READLINKAT:        makeSyscallSignature("readlinkat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_FCHMODAT:          makeSyscallSignature("fchmodat", ParamTypeAny, ParamTypePath, ParamTypeAny),
	unix.SYS_FACCESSAT:         makeSyscallSignature("faccessat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_PSELECT6:          makeSyscallSignature("pselect6", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PPOLL:             makeSyscallSignature("ppoll", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_UNSHARE:           makeSyscallSignature("unshare", ParamTypeAny),
	unix.SYS_SET_ROBUST_LIST:   makeSyscallSignature("set_robust_list", ParamTypeAny, ParamTypeAny),
	unix.SYS_GET_ROBUST_LIST:   makeSyscallSignature("get_robust_list", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SPLICE:            makeSyscallSignature("splice", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TEE:               makeSyscallSignature("tee", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SYNC_FILE_RANGE:   makeSyscallSignature("sync_file_range", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_VMSPLICE:          makeSyscallSignature("vmsplice", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MOVE_PAGES:        makeSyscallSignature("move_pages", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_UTIMENSAT:         makeSyscallSignature("utimensat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
	unix.SYS_EPOLL_PWAIT:       makeSyscallSignature("epoll_pwait", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SIGNALFD:          makeSyscallSignature("signalfd", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TIMERFD_CREATE:    makeSyscallSignature("timerfd_create", ParamTypeAny, ParamTypeAny),
	unix.SYS_EVENTFD:           makeSyscallSignature("eventfd", ParamTypeAny),
	unix.SYS_FALLOCATE:         makeSyscallSignature("fallocate", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TIMERFD_SETTIME:   makeSyscallSignature("timerfd_settime", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_TIMERFD_GETTIME:   makeSyscallSignature("timerfd_gettime", ParamTypeAny, ParamTypeAny),
	unix.SYS_ACCEPT4:           makeSyscallSignature("accept4", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SIGNALFD4:         makeSyscallSignature("signalfd4", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_EVENTFD2:          makeSyscallSignature("eventfd2", ParamTypeAny, ParamTypeAny),
	unix.SYS_EPOLL_CREATE1:     makeSyscallSignature("epoll_create1", ParamTypeAny),
	unix.SYS_DUP3:              makeSyscallSignature("dup3", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PIPE2:             makeSyscallSignature("pipe2", ParamTypeAny, ParamTypeAny),
	unix.SYS_INOTIFY_INIT1:     makeSyscallSignature("inotify_init1", ParamTypeAny),
	unix.SYS_PREADV:            makeSyscallSignature("preadv", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PWRITEV:           makeSyscallSignature("pwritev", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RT_TGSIGQUEUEINFO: makeSyscallSignature("rt_tgsigqueueinfo", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PERF_EVENT_OPEN:   makeSyscallSignature("perf_event_open", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RECVMMSG:          makeSyscallSignature("recvmmsg", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FANOTIFY_INIT:     makeSyscallSignature("fanotify_init", ParamTypeAny, ParamTypeAny),
	unix.SYS_FANOTIFY_MARK:     makeSyscallSignature("fanotify_mark", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PRLIMIT64:         makeSyscallSignature("prlimit64", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_NAME_TO_HANDLE_AT: makeSyscallSignature("name_to_handle_at", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_OPEN_BY_HANDLE_AT: makeSyscallSignature("open_by_handle_at", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_CLOCK_ADJTIME:     makeSyscallSignature("clock_adjtime", ParamTypeAny, ParamTypeAny),
	unix.SYS_SYNCFS:            makeSyscallSignature("syncfs", ParamTypeAny),
	unix.SYS_SENDMMSG:          makeSyscallSignature("sendmmsg", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SETNS:             makeSyscallSignature("setns", ParamTypeAny, ParamTypeAny),
	unix.SYS_GETCPU:            makeSyscallSignature("getcpu", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PROCESS_VM_READV:  makeSyscallSignature("process_vm_readv", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PROCESS_VM_WRITEV: makeSyscallSignature("process_vm_writev", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_KCMP:              makeSyscallSignature("kcmp", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FINIT_MODULE:      makeSyscallSignature("finit_module", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_SETATTR:     makeSyscallSignature("sched_setattr", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_SCHED_GETATTR:     makeSyscallSignature("sched_getattr", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_RENAMEAT2:         makeSyscallSignature("renameat2", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypePath, ParamTypeAny),
	unix.SYS_SECCOMP:           makeSyscallSignature("seccomp", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_GETRANDOM:         makeSyscallSignature("getrandom", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MEMFD_CREATE:      makeSyscallSignature("memfd_create", ParamTypeAny, ParamTypeAny),
	unix.SYS_KEXEC_FILE_LOAD:   makeSyscallSignature("kexec_file_load", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_BPF:               makeSyscallSignature("bpf", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_EXECVEAT:          makeSyscallSignature("execveat", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_USERFAULTFD:       makeSyscallSignature("userfaultfd", ParamTypeAny),
	unix.SYS_MEMBARRIER:        makeSyscallSignature("membarrier", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_MLOCK2:            makeSyscallSignature("mlock2", ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_COPY_FILE_RANGE:   makeSyscallSignature("copy_file_range", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PREADV2:           makeSyscallSignature("preadv2", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PWRITEV2:          makeSyscallSignature("pwritev2", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PKEY_MPROTECT:     makeSyscallSignature("pkey_mprotect", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_PKEY_ALLOC:        makeSyscallSignature("pkey_alloc", ParamTypeAny, ParamTypeAny),
	unix.SYS_PKEY_FREE:         makeSyscallSignature("pkey_free", ParamTypeAny),
	unix.SYS_STATX:             makeSyscallSignature("statx", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_IO_URING_SETUP:    makeSyscallSignature("io_uring_setup", ParamTypeAny, ParamTypeAny),
	unix.SYS_IO_URING_ENTER:    makeSyscallSignature("io_uring_setup", ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny, ParamTypeAny),
	unix.SYS_FACCESSAT2:        makeSyscallSignature("faccessat2", ParamTypeAny, ParamTypePath, ParamTypeAny, ParamTypeAny),
}
