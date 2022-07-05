package gsandbox

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/souk4711/gsandbox/pkg/ptrace"
)

func (e *Executor) applySyscallFilterWhenEnter(curr *ptrace.Syscall) (error, error) {
	// prepare data from regs
	for _, arg := range curr.GetArgs() {
		if err := arg.Read(); err != nil {
			return nil, fmt.Errorf("ptrace: %s", err.Error())
		}
	}

	// logging
	var name = curr.GetName()
	var args = make([]string, len(curr.GetArgs()))
	for i, arg := range curr.GetArgs() {
		args[i] = arg.String()
	}
	e.logger.Info(fmt.Sprintf("syscall: Enter: %s(%s)", name, strings.Join(args, ", ")))

	// filter - allowable
	r1, err := e.applySyscallFilterWhenEnter_Allowable(curr)
	if err != nil || r1 != nil {
		return r1, err
	}

	// filter - fs
	r2, err := e.applySyscallFilterWhenEnter_FileAccessControl(curr)
	if err != nil || r2 != nil {
		return r2, err
	}

	// ok
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenEnter_Allowable(curr *ptrace.Syscall) (error, error) {
	if _, ok := e.allowedSyscalls[curr.GetName()]; !ok {
		err := fmt.Errorf("syscall: IllegalCall: func(%s)", curr.GetName())
		return err, nil
	}
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenEnter_FileAccessControl(curr *ptrace.Syscall) (error, error) {
	var dirfd int = unix.AT_FDCWD
	var path string = "/invalidpath"
	var dirfd2 int = unix.AT_FDCWD
	var path2 string = "/invalidpath"

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
	case unix.SYS_ACCESS, unix.SYS_FACCESSAT:
		switch nr {
		case unix.SYS_ACCESS:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FACCESSAT:
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
	case unix.SYS_DUP, unix.SYS_DUP2, unix.SYS_DUP3:
		goto PASSTHROUGH

	// not implemented
	default:
		for _, arg := range curr.GetArgs() {
			if arg.IsParamType(ptrace.ParamTypeFd) || arg.IsParamType(ptrace.ParamTypePath) {
				err := fmt.Errorf("fsfilter: NotImplemented: %s", curr.GetName())
				return err, nil
			}
		}
		return nil, nil
	}

CHECK_READABLE:
	if ok, _ := e.fsfilter.AllowRead(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: ReadDisallowed: path(%s), dirfd(%d)", path, dirfd)
		return err, nil
	} else {
		e.logger.Info("syscall: Enter:   => fsfilter: ReadAllowed")
		return nil, nil
	}

CHECK_WRITEABLE:
	if ok, _ := e.fsfilter.AllowWrite(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: WriteDisallowed: path(%s), dirfd(%d)", path, dirfd)
		return err, nil
	} else {
		e.logger.Info("syscall: Enter:   => fsfiter: WriteAllowed")
		return nil, nil
	}

CHECK_WRITEABLE_2:
	if ok, _ := e.fsfilter.AllowWrite(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: WriteDisallowed: path(%s), dirfd(%d), path2(%s), dirfd2(%d)", path, dirfd, path2, dirfd2)
		return err, nil
	} else if ok, _ := e.fsfilter.AllowWrite(path2, dirfd2); !ok {
		err := fmt.Errorf("fsfilter: WriteDisallowed: path(%s), dirfd(%d), path2(%s), dirfd2(%d)", path, dirfd, path2, dirfd2)
		return err, nil
	} else {
		e.logger.Info("syscall: Enter:   => fsfiter: WriteAllowed")
		return nil, nil
	}

CHECK_EXECUTABLE:
	if ok, _ := e.fsfilter.AllowExecute(path, dirfd); !ok {
		err := fmt.Errorf("fsfilter: ExecuteDisallowed: path(%s), dirfd(%d)", path, dirfd)
		return err, nil
	} else {
		e.logger.Info("syscall: Enter:   => fsfilter: ExecuteAllowed")
		return nil, nil
	}

PASSTHROUGH:
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenLeave(curr *ptrace.Syscall, prev *ptrace.Syscall) (error, error) {
	// prepare data from regs
	var retval = curr.GetRetval()
	if err := retval.Read(); err != nil {
		return nil, fmt.Errorf("ptrace: %s", err.Error())
	}

	// ENOSYS - which is put into RAX as a default return value by the kernel's syscall entry code
	if retval.HasError_ENOSYS() {
		return nil, fmt.Errorf("ptrace - %s", syscall.ENOSYS)
	}

	// track fd
	r1, err := e.applySyscallFilterWhenLeave_TrackFd(curr, prev)
	if err != nil || r1 != nil {
		return r1, err
	}

	// logging
	e.logger.Info(fmt.Sprintf("syscall: Leave:   => retval: %s", retval))

	// ok
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenLeave_TrackFd(curr *ptrace.Syscall, prev *ptrace.Syscall) (error, error) {
	var retval = curr.GetRetval()
	if retval.HasError() {
		return nil, nil
	}

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
		if err := e.fsfilter.TrackFd(retval.GetValue(), path, dirfd); err != nil {
			return nil, fmt.Errorf("ptrace: %s", err.Error())
		}
		e.logger.Info(fmt.Sprintf("syscall: Leave:   => fsfilter: TRACK: %s <=> %s", ptrace.Fd(retval.GetValue()), path))

	// close
	case unix.SYS_CLOSE:
		var fd = prev.GetArg(0).GetFd()
		e.fsfilter.UntrackFd(fd)
		e.logger.Info(fmt.Sprintf("syscall: Leave:   => fsfilter: UNTRACK: %s", ptrace.Fd(fd)))

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

		f, err := e.fsfilter.GetTrackdFile(oldfd)
		if err != nil {
			return nil, fmt.Errorf("ptrace: %s", err.Error())
		}
		if err := e.fsfilter.TrackFd(retval.GetValue(), f.GetFullpath(), newfd); err != nil {
			return nil, fmt.Errorf("ptrace: %s", err.Error())
		}
		e.logger.Info(fmt.Sprintf("syscall: Leave:   => fsfilter: TRACK: %s <=> %s <=> %s", ptrace.Fd(newfd), ptrace.Fd(oldfd), f.GetFullpath()))
	}

	return nil, nil
}
