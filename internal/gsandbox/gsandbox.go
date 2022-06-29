package gsandbox

import (
	_ "embed"
	"os"
	"runtime"

	"github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"
	"github.com/goccy/go-json"
)

var (
	version = &Version{
		Name:      "Gsandbox",
		Number:    "0.0.1",
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		ARCH:      runtime.GOARCH,
	}
)

var (
	//go:embed embed/policy.json
	defaultPolicyData []byte
)

var (
	// The default seccomp syscall allowlist provides a sane default for running sandbox
	// with seccomp and disables around 44 system calls out of 300+. It is moderately
	// protective while providing wide application compatibility.
	//
	// Plz see https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
	seccompSyscallsAllowlist = []string{
		"accept",
		"accept4",
		"access",
		"adjtimex",
		"alarm",
		"bind",
		"brk",
		"capget",
		"capset",
		"chdir",
		"chmod",
		"chown",
		"chown32",
		"clock_adjtime",
		"clock_adjtime64",
		"clock_getres",
		"clock_getres_time64",
		"clock_gettime",
		"clock_gettime64",
		"clock_nanosleep",
		"clock_nanosleep_time64",
		"close",
		"close_range",
		"connect",
		"copy_file_range",
		"creat",
		"dup",
		"dup2",
		"dup3",
		"epoll_create",
		"epoll_create1",
		"epoll_ctl",
		"epoll_ctl_old",
		"epoll_pwait",
		"epoll_pwait2",
		"epoll_wait",
		"epoll_wait_old",
		"eventfd",
		"eventfd2",
		"execve",
		"execveat",
		"exit",
		"exit_group",
		"faccessat",
		"faccessat2",
		"fadvise64",
		"fadvise64_64",
		"fallocate",
		"fanotify_mark",
		"fchdir",
		"fchmod",
		"fchmodat",
		"fchown",
		"fchown32",
		"fchownat",
		"fcntl",
		"fcntl64",
		"fdatasync",
		"fgetxattr",
		"flistxattr",
		"flock",
		"fork",
		"fremovexattr",
		"fsetxattr",
		"fstat",
		"fstat64",
		"fstatat64",
		"fstatfs",
		"fstatfs64",
		"fsync",
		"ftruncate",
		"ftruncate64",
		"futex",
		"futex_time64",
		"futex_waitv",
		"futimesat",
		"getcpu",
		"getcwd",
		"getdents",
		"getdents64",
		"getegid",
		"getegid32",
		"geteuid",
		"geteuid32",
		"getgid",
		"getgid32",
		"getgroups",
		"getgroups32",
		"getitimer",
		"getpeername",
		"getpgid",
		"getpgrp",
		"getpid",
		"getppid",
		"getpriority",
		"getrandom",
		"getresgid",
		"getresgid32",
		"getresuid",
		"getresuid32",
		"getrlimit",
		"get_robust_list",
		"getrusage",
		"getsid",
		"getsockname",
		"getsockopt",
		"get_thread_area",
		"gettid",
		"gettimeofday",
		"getuid",
		"getuid32",
		"getxattr",
		"inotify_add_watch",
		"inotify_init",
		"inotify_init1",
		"inotify_rm_watch",
		"io_cancel",
		"ioctl",
		"io_destroy",
		"io_getevents",
		"io_pgetevents",
		"io_pgetevents_time64",
		"ioprio_get",
		"ioprio_set",
		"io_setup",
		"io_submit",
		"io_uring_enter",
		"io_uring_register",
		"io_uring_setup",
		"ipc",
		"kill",
		"landlock_add_rule",
		"landlock_create_ruleset",
		"landlock_restrict_self",
		"lchown",
		"lchown32",
		"lgetxattr",
		"link",
		"linkat",
		"listen",
		"listxattr",
		"llistxattr",
		"_llseek",
		"lremovexattr",
		"lseek",
		"lsetxattr",
		"lstat",
		"lstat64",
		"madvise",
		"membarrier",
		"memfd_create",
		"memfd_secret",
		"mincore",
		"mkdir",
		"mkdirat",
		"mknod",
		"mknodat",
		"mlock",
		"mlock2",
		"mlockall",
		"mmap",
		"mmap2",
		"mprotect",
		"mq_getsetattr",
		"mq_notify",
		"mq_open",
		"mq_timedreceive",
		"mq_timedreceive_time64",
		"mq_timedsend",
		"mq_timedsend_time64",
		"mq_unlink",
		"mremap",
		"msgctl",
		"msgget",
		"msgrcv",
		"msgsnd",
		"msync",
		"munlock",
		"munlockall",
		"munmap",
		"nanosleep",
		"newfstatat",
		"_newselect",
		"open",
		"openat",
		"openat2",
		"pause",
		"pidfd_open",
		"pidfd_send_signal",
		"pipe",
		"pipe2",
		"poll",
		"ppoll",
		"ppoll_time64",
		"prctl",
		"pread64",
		"preadv",
		"preadv2",
		"prlimit64",
		"process_mrelease",
		"pselect6",
		"pselect6_time64",
		"pwrite64",
		"pwritev",
		"pwritev2",
		"read",
		"readahead",
		"readlink",
		"readlinkat",
		"readv",
		"recv",
		"recvfrom",
		"recvmmsg",
		"recvmmsg_time64",
		"recvmsg",
		"remap_file_pages",
		"removexattr",
		"rename",
		"renameat",
		"renameat2",
		"restart_syscall",
		"rmdir",
		"rseq",
		"rt_sigaction",
		"rt_sigpending",
		"rt_sigprocmask",
		"rt_sigqueueinfo",
		"rt_sigreturn",
		"rt_sigsuspend",
		"rt_sigtimedwait",
		"rt_sigtimedwait_time64",
		"rt_tgsigqueueinfo",
		"sched_getaffinity",
		"sched_getattr",
		"sched_getparam",
		"sched_get_priority_max",
		"sched_get_priority_min",
		"sched_getscheduler",
		"sched_rr_get_interval",
		"sched_rr_get_interval_time64",
		"sched_setaffinity",
		"sched_setattr",
		"sched_setparam",
		"sched_setscheduler",
		"sched_yield",
		"seccomp",
		"select",
		"semctl",
		"semget",
		"semop",
		"semtimedop",
		"semtimedop_time64",
		"send",
		"sendfile",
		"sendfile64",
		"sendmmsg",
		"sendmsg",
		"sendto",
		"setfsgid",
		"setfsgid32",
		"setfsuid",
		"setfsuid32",
		"setgid",
		"setgid32",
		"setgroups",
		"setgroups32",
		"setitimer",
		"setpgid",
		"setpriority",
		"setregid",
		"setregid32",
		"setresgid",
		"setresgid32",
		"setresuid",
		"setresuid32",
		"setreuid",
		"setreuid32",
		"setrlimit",
		"set_robust_list",
		"setsid",
		"setsockopt",
		"set_thread_area",
		"set_tid_address",
		"setuid",
		"setuid32",
		"setxattr",
		"shmat",
		"shmctl",
		"shmdt",
		"shmget",
		"shutdown",
		"sigaltstack",
		"signalfd",
		"signalfd4",
		"sigprocmask",
		"sigreturn",
		"socket",
		"socketcall",
		"socketpair",
		"splice",
		"stat",
		"stat64",
		"statfs",
		"statfs64",
		"statx",
		"symlink",
		"symlinkat",
		"sync",
		"sync_file_range",
		"syncfs",
		"sysinfo",
		"tee",
		"tgkill",
		"time",
		"timer_create",
		"timer_delete",
		"timer_getoverrun",
		"timer_gettime",
		"timer_gettime64",
		"timer_settime",
		"timer_settime64",
		"timerfd_create",
		"timerfd_gettime",
		"timerfd_gettime64",
		"timerfd_settime",
		"timerfd_settime64",
		"times",
		"tkill",
		"truncate",
		"truncate64",
		"ugetrlimit",
		"umask",
		"uname",
		"unlink",
		"unlinkat",
		"utime",
		"utimensat",
		"utimensat_time64",
		"utimes",
		"vfork",
		"vmsplice",
		"wait4",
		"waitid",
		"waitpid",
		"write",
		"writev",
	}

	// Required by Gsandbox.
	seccompSyscallsAllowlist4Gsandbox = []string{
		"arch_prctl",
		"clone",
	}
)

func GetVersion() *Version {
	return version
}

// Since Golang heavily uses OS-level threads to power its goroutine scheduling. There
// is no easy way to set resource limit or seccomp filter in child process. Set it in
// parent process, then inherits it.
//
// Plz see https://stackoverflow.com/questions/28370646/how-do-i-fork-a-go-process
func Run(prog string, args []string, policyFilePath string) (*Result, error) {
	policy, err := runBuildPolicyFromPath(policyFilePath)
	if err != nil {
		return nil, err
	}

	seccompPolicy, err := runBuildSeccompPolicy(policy)
	if err != nil {
		return nil, err
	}

	var e = &Executor{Prog: prog, Args: args, SeccompPolicy: seccompPolicy}
	e.Limits = policy.Limits

	return e.Run(), nil
}

func runBuildPolicyFromPath(policyFilePath string) (*Policy, error) {
	var policyData *[]byte
	if policyFilePath != "" {
		data, err := os.ReadFile(policyFilePath)
		if err != nil {
			return nil, err
		}

		policyData = &data
	} else {
		policyData = &defaultPolicyData
	}

	var policy = &Policy{}
	if err := json.Unmarshal(*policyData, policy); err != nil {
		return nil, err
	}

	return policy, nil
}

func runBuildSeccompPolicy(_ *Policy) (*seccomp.Policy, error) {
	var arch, err = arch.GetInfo("")
	if err != nil {
		return nil, err
	}

	var syscallsAllowList = append(seccompSyscallsAllowlist, seccompSyscallsAllowlist4Gsandbox...)
	var syscalls = []string{}
	for _, name := range syscallsAllowList {
		if _, ok := arch.SyscallNames[name]; ok {
			syscalls = append(syscalls, name)
		}
	}

	var seccompPolicy = &seccomp.Policy{
		DefaultAction: seccomp.ActionErrno,
		Syscalls:      []seccomp.SyscallGroup{{Action: seccomp.ActionAllow, Names: syscalls}},
	}

	return seccompPolicy, nil
}
