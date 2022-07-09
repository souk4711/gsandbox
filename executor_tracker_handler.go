package gsandbox

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/souk4711/gsandbox/pkg/fsfilter"
	"github.com/souk4711/gsandbox/pkg/ptrace"
	"golang.org/x/sys/unix"
)

func (e *Executor) HandleTracerPanicEvent(err error) {
	e.setResultWithSandboxFailure(err)
}

func (e *Executor) HandleTracerExitedEvent(pid int, ws syscall.WaitStatus, rusage syscall.Rusage) {
	e.infoWithPid("syscall: Event: ExitedEvent", pid)
	if pid == e.cmd.Process.Pid {
		e.setResultWithOK(&ws, &rusage)
	}
}

func (e *Executor) HandleTracerSignaledEvent(pid int, ws syscall.WaitStatus, rusage syscall.Rusage) {
	e.infoWithPid("syscall: Event: SignaledEvent", pid)
	if pid == e.cmd.Process.Pid {
		e.setResult(&ws, &rusage)
	}
}

func (e *Executor) HandleTracerNewChildEvent(parentPid int, childPid int) {
	e.infoWithPid(fmt.Sprintf("syscall: Event: NewChildEvent(%d)", childPid), parentPid)
	parentFsFilter := e.traceeFsFilters[parentPid]
	childFsFilter := fsfilter.NewFsFilterInheritFromParent(childPid, parentFsFilter)
	e.traceeFsFilters[childPid] = childFsFilter
}

func (e *Executor) HandleTracerSyscallEnterEvent(pid int, curr *ptrace.Syscall) (continued bool) {
	e.traceePid = pid
	defer func() {
		e.traceePid = 0
	}()

	// prepare data from regs
	for _, arg := range curr.GetArgs() {
		if err := arg.Read(); err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			e.setResultWithSandboxFailure(err)
			return false
		}
	}

	// logging
	var name = curr.GetName()
	var args = make([]string, len(curr.GetArgs()))
	for i, arg := range curr.GetArgs() {
		args[i] = arg.String()
	}
	e.info(fmt.Sprintf("syscall: Enter: %s(%s)", name, strings.Join(args, ", ")))

	// filter - restrict syscall access
	if continued := e.HandleTracerSyscallEnterEvent_CheckSyscallAccess(pid, curr); !continued {
		return false
	}

	// filter - restrict file access
	if continued := e.HandleTracerSyscallEnterEvent_CheckFileAccess(pid, curr); !continued {
		return false
	}

	// ok
	return true
}

func (e *Executor) HandleTracerSyscallEnterEvent_CheckSyscallAccess(pid int, curr *ptrace.Syscall) (continued bool) {
	if _, ok := e.allowedSyscalls[curr.GetName()]; !ok {
		err := fmt.Errorf("syscall: IllegalCall: func(%s)", curr.GetName())
		e.setResultWithViolation(err)
		return false
	}
	return true
}

func (e *Executor) HandleTracerSyscallEnterEvent_CheckFileAccess(pid int, curr *ptrace.Syscall) (continued bool) {
	var (
		dirfd  int    = unix.AT_FDCWD
		path   string = "/gsandbox-invalidpath-9Qo0MIVp2fDiGKVbvdaIqw"
		dirfd2 int    = unix.AT_FDCWD
		path2  string = "/gsandbox-invalidpath-9Qo0MIVp2fDiGKVbvdaIqw"
		filter *fsfilter.FsFilter
	)

	var nr = curr.GetNR()
	switch nr {
	// read
	case unix.SYS_READ:
		dirfd = curr.GetArg(0).GetFd()
		path = ""
		goto CHECK_READABLE

	// write
	case unix.SYS_WRITE:
		dirfd = curr.GetArg(0).GetFd()
		path = ""
		goto CHECK_WRITEABLE

	// open
	case unix.SYS_OPEN, unix.SYS_OPENAT, unix.SYS_CREAT:
		var flag int
		switch nr {
		case unix.SYS_OPEN:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
			flag = curr.GetArg(1).GetFlag()
		case unix.SYS_OPENAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
			flag = curr.GetArg(2).GetFlag()
		case unix.SYS_CREAT:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
			flag = unix.O_CREAT | unix.O_WRONLY | unix.O_TRUNC
		}

		flag = flag &^ unix.O_CLOEXEC
		flag = flag &^ unix.O_NONBLOCK
		flag = flag &^ unix.O_TMPFILE
		if flag == os.O_RDONLY {
			goto CHECK_READABLE
		} else {
			goto CHECK_WRITEABLE
		}

	// stat
	case unix.SYS_STAT, unix.SYS_FSTAT, unix.SYS_LSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STATX:
		switch nr {
		case unix.SYS_STAT:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_LSTAT:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FSTAT:
			dirfd = curr.GetArg(0).GetFd()
			path = ""
		case unix.SYS_NEWFSTATAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		case unix.SYS_STATX:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_READABLE

	// access
	case unix.SYS_ACCESS, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2:
		switch nr {
		case unix.SYS_ACCESS:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FACCESSAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		case unix.SYS_FACCESSAT2:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_READABLE

	// rename
	case unix.SYS_RENAME, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
		switch nr {
		case unix.SYS_RENAME:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
			dirfd2 = unix.AT_FDCWD
			path2 = curr.GetArg(1).GetPath()
		case unix.SYS_RENAMEAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
			dirfd2 = curr.GetArg(2).GetFd()
			path2 = curr.GetArg(3).GetPath()
		case unix.SYS_RENAMEAT2:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
			dirfd2 = curr.GetArg(2).GetFd()
			path2 = curr.GetArg(3).GetPath()
		}
		goto CHECK_WRITEABLE_2

	// chdir
	case unix.SYS_CHDIR, unix.SYS_FCHDIR:
		switch nr {
		case unix.SYS_CHDIR:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FCHDIR:
			dirfd = curr.GetArg(0).GetFd()
			path = ""
		}
		goto CHECK_READABLE

	// mkdir
	case unix.SYS_MKDIR, unix.SYS_MKDIRAT:
		switch nr {
		case unix.SYS_MKDIR:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_MKDIRAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_WRITEABLE

	// readlink
	case unix.SYS_READLINK, unix.SYS_READLINKAT:
		switch nr {
		case unix.SYS_READLINK:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_READLINKAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_READABLE

	// link
	case unix.SYS_LINK, unix.SYS_LINKAT:
		switch nr {
		case unix.SYS_LINK:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
			dirfd2 = unix.AT_FDCWD
			path2 = curr.GetArg(1).GetPath()
		case unix.SYS_LINKAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
			dirfd2 = curr.GetArg(2).GetFd()
			path2 = curr.GetArg(3).GetPath()
		}
		goto CHECK_WRITEABLE_2

	// symlink
	case unix.SYS_SYMLINK, unix.SYS_SYMLINKAT:
		switch nr {
		case unix.SYS_SYMLINK:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
			dirfd2 = unix.AT_FDCWD
			path2 = curr.GetArg(1).GetPath()
		case unix.SYS_SYMLINKAT:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
			dirfd2 = curr.GetArg(1).GetFd()
			path2 = curr.GetArg(2).GetPath()
		}
		goto CHECK_WRITEABLE_2

	// unlink
	case unix.SYS_UNLINK, unix.SYS_UNLINKAT:
		switch nr {
		case unix.SYS_UNLINK:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_UNLINKAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_WRITEABLE

	// chmod
	case unix.SYS_CHMOD, unix.SYS_FCHMOD, unix.SYS_FCHMODAT:
		switch nr {
		case unix.SYS_CHMOD:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FCHMOD:
			dirfd = curr.GetArg(0).GetFd()
			path = ""
		case unix.SYS_FCHMODAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_WRITEABLE

	// statfs
	case unix.SYS_STATFS, unix.SYS_FSTATFS:
		switch nr {
		case unix.SYS_STATFS:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FSTATFS:
			dirfd = curr.GetArg(0).GetFd()
			path = ""
		}
		goto CHECK_READABLE

	// getxattr
	case unix.SYS_GETXATTR, unix.SYS_LGETXATTR, unix.SYS_FGETXATTR:
		switch nr {
		case unix.SYS_GETXATTR:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_LGETXATTR:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FGETXATTR:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_READABLE

	// execve
	case unix.SYS_EXECVE, unix.SYS_EXECVEAT:
		switch nr {
		case unix.SYS_EXECVE:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_EXECVEAT:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
		}
		goto CHECK_EXECUTABLE

	// pass through
	case unix.SYS_CLOSE:
		goto PASSTHROUGH
	case unix.SYS_PIPE, unix.SYS_PIPE2:
		goto PASSTHROUGH
	case unix.SYS_DUP, unix.SYS_DUP2, unix.SYS_DUP3:
		goto PASSTHROUGH
	case unix.SYS_FCNTL:
		goto PASSTHROUGH

	// not implemented
	default:
		// fs-related syscall?
		for _, arg := range curr.GetArgs() {
			if arg.IsParamType(ptrace.ParamTypeFd) || arg.IsParamType(ptrace.ParamTypePath) {
				err := fmt.Errorf("fsfilter: NotImplemented: %s", curr.GetName())
				e.setResultWithViolation(err)
				return false
			}
		}

		// .
		return true
	}

CHECK_READABLE:
	filter = e.traceeFsFilters[pid]
	if ok, _ := filter.AllowRead(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: ReadDisallowed: path(%s), dirfd(%d)", path, dirfd)
		e.setResultWithViolation(err)
		return false
	} else {
		e.info("syscall: Enter:   => fsfilter: ReadAllowed")
		return true
	}

CHECK_WRITEABLE:
	filter = e.traceeFsFilters[pid]
	if ok, _ := filter.AllowWrite(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: WriteDisallowed: path(%s), dirfd(%d)", path, dirfd)
		e.setResultWithViolation(err)
		return false
	} else {
		e.info("syscall: Enter:   => fsfiter: WriteAllowed")
		return true
	}

CHECK_WRITEABLE_2:
	filter = e.traceeFsFilters[pid]
	if ok, _ := filter.AllowWrite(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: WriteDisallowed: path(%s), dirfd(%d), path2(%s), dirfd2(%d)", path, dirfd, path2, dirfd2)
		e.setResultWithViolation(err)
		return false
	} else if ok, _ := filter.AllowWrite(path2, dirfd2); !ok {
		err := fmt.Errorf("fsfilter: WriteDisallowed: path(%s), dirfd(%d), path2(%s), dirfd2(%d)", path, dirfd, path2, dirfd2)
		e.setResultWithViolation(err)
		return false
	} else {
		e.info("syscall: Enter:   => fsfiter: WriteAllowed")
		return true
	}

CHECK_EXECUTABLE:
	filter = e.traceeFsFilters[pid]
	if ok, _ := filter.AllowExecute(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: ExecuteDisallowed: path(%s), dirfd(%d)", path, dirfd)
		e.setResultWithViolation(err)
		return false
	} else {
		e.info("syscall: Enter:   => fsfilter: ExecuteAllowed")
		return true
	}

PASSTHROUGH:
	return true
}

func (e *Executor) HandleTracerSyscallLeaveEvent(pid int, curr *ptrace.Syscall, prev *ptrace.Syscall) (continued bool) {
	e.traceePid = pid
	defer func() {
		e.traceePid = 0
	}()

	// special case
	if curr.GetNR() == unix.SYS_EXIT || curr.GetNR() == unix.SYS_EXIT_GROUP {
		e.info("syscall: Leave:   => retval: ?")
		return true
	}

	// prepare data from regs
	var retval = curr.GetRetval()
	if err := retval.Read(); err != nil {
		e.setResultWithSandboxFailure(fmt.Errorf("ptrace: %s", err.Error()))
		return false
	}

	// ENOSYS - which is put into RAX as a default return value by the kernel's syscall entry code
	if retval.HasError_ENOSYS() {
		e.info(fmt.Sprintf("syscall: Leave:   => retval: %s", retval))
		e.setResultWithSandboxFailure(fmt.Errorf("ptrace: ENOSYS: %s(...) = %s", curr.GetName(), syscall.ENOSYS))
		return false
	}

	// track fd
	if continued := e.HandleTracerSyscallLeaveEvent_TraceFd(pid, curr, prev); !continued {
		return false
	}

	// logging
	e.info(fmt.Sprintf("syscall: Leave:   => retval: %s", retval))

	// ok
	return true
}

func (e *Executor) HandleTracerSyscallLeaveEvent_TraceFd(pid int, curr *ptrace.Syscall, prev *ptrace.Syscall) (continued bool) {
	var retval = curr.GetRetval()
	if retval.HasError() {
		return true
	}

	var filter = e.traceeFsFilters[pid]
	var nr = curr.GetNR()
	switch nr {
	// open
	case unix.SYS_OPEN, unix.SYS_OPENAT, unix.SYS_CREAT:
		var dirfd int
		var path string
		switch nr {
		case unix.SYS_OPEN:
			dirfd = unix.AT_FDCWD
			path = prev.GetArg(0).GetPath()
		case unix.SYS_OPENAT:
			dirfd = prev.GetArg(0).GetFd()
			path = prev.GetArg(1).GetPath()
		case unix.SYS_CREAT:
			dirfd = unix.AT_FDCWD
			path = prev.GetArg(0).GetPath()
		}

		f, err := filter.TrackFd(retval.GetValue(), path, dirfd)
		if err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			e.setResultWithSandboxFailure(err)
			return false
		}
		e.info(fmt.Sprintf("syscall: Leave:   => fsfilter: TRACK: %s <=> %s", ptrace.Fd(retval.GetValue()), f.GetFullpath()))

	// close
	case unix.SYS_CLOSE:
		var fd = prev.GetArg(0).GetFd()
		filter.UntrackFd(fd)
		e.info(fmt.Sprintf("syscall: Leave:   => fsfilter: UNTRACK: %s", ptrace.Fd(fd)))

	// pipe
	case unix.SYS_PIPE, unix.SYS_PIPE2:
		if err := curr.GetArg(0).Read(); err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			e.setResultWithSandboxFailure(err)
			return
		}
		var pipefd = curr.GetArg(0).GetPipeFd()
		var fd_rd = pipefd[0]
		var fd_wr = pipefd[1]
		if f, err := filter.TrackMemFd(fd_rd, fsfilter.FILE_RD); err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			e.setResultWithSandboxFailure(err)
			return false
		} else {
			e.info(fmt.Sprintf("syscall: Leave:   => fsfilter: TRACK: %s <=> %s", ptrace.Fd(fd_rd), f.GetFullpath()))
		}
		if f, err := filter.TrackMemFd(fd_wr, fsfilter.FILE_WR); err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			e.setResultWithSandboxFailure(err)
			return false
		} else {
			e.info(fmt.Sprintf("syscall: Leave:   => fsfilter: TRACK: %s <=> %s", ptrace.Fd(fd_wr), f.GetFullpath()))
		}
		e.info(fmt.Sprintf("syscall: Leave:   =>   arg0: %s", curr.GetArg(0).String()))

	// dup
	case unix.SYS_DUP, unix.SYS_DUP2, unix.SYS_DUP3:
		var oldfd int
		var newfd int
		switch nr {
		case unix.SYS_DUP:
			oldfd = prev.GetArg(0).GetFd()
			newfd = retval.GetValue()
		case unix.SYS_DUP2:
			oldfd = prev.GetArg(0).GetFd()
			newfd = retval.GetValue()
		case unix.SYS_DUP3:
			oldfd = prev.GetArg(0).GetFd()
			newfd = retval.GetValue()
		}

		f, err := filter.GetTrackdFile(oldfd)
		if err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			e.setResultWithSandboxFailure(err)
			return false
		}
		if _, err := filter.TrackFd(retval.GetValue(), f.GetFullpath(), unix.AT_FDCWD); err != nil {
			err = fmt.Errorf("ptrace: %s", err.Error())
			e.setResultWithSandboxFailure(err)
			return false
		}
		e.info(fmt.Sprintf("syscall: Leave:   => fsfilter: TRACK: %s <=> %s <=> %s", ptrace.Fd(newfd), ptrace.Fd(oldfd), f.GetFullpath()))

	// fcntl
	case unix.SYS_FCNTL:
		var oldfd = prev.GetArg(0).GetFd()
		var cmd = prev.GetArg(1).GetFlag()
		switch cmd {
		case unix.F_GETFD:
			break
		case unix.F_SETFD:
			break
		case unix.F_GETFL:
			break
		case unix.F_SETFL:
			break
		case unix.F_DUPFD:
			var newfd = retval.GetValue()
			f, err := filter.GetTrackdFile(oldfd)
			if err != nil {
				err = fmt.Errorf("ptrace: %s", err.Error())
				e.setResultWithSandboxFailure(err)
				return false
			}
			if _, err := filter.TrackFd(newfd, f.GetFullpath(), unix.AT_FDCWD); err != nil {
				err = fmt.Errorf("ptrace: %s", err.Error())
				e.setResultWithSandboxFailure(err)
				return false
			}
			e.info(fmt.Sprintf("syscall: Leave:   => fsfilter: TRACK: %s <=> %s <=> %s", ptrace.Fd(newfd), ptrace.Fd(oldfd), f.GetFullpath()))
		default:
			err := fmt.Errorf("fsfilter: NotImplemented: %s(%s, %s, ...)", curr.GetName(), ptrace.Fd(oldfd), ptrace.FlagFcntlCmd(cmd))
			e.setResultWithViolation(err)
			return false
		}
	}

	return true
}
