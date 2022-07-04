package gsandbox

import (
	"fmt"
	"os"
	"strings"

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

		if flag&^unix.O_CLOEXEC == os.O_RDONLY {
			goto CHECK_READABLE
		} else {
			goto CHECK_WRITEABLE
		}

	// stat
	case unix.SYS_STAT, unix.SYS_FSTAT, unix.SYS_LSTAT, unix.SYS_NEWFSTATAT:
		switch nr {
		case unix.SYS_STAT, unix.SYS_LSTAT:
			dirfd = unix.AT_FDCWD
			path = curr.GetArg(0).GetPath()
		case unix.SYS_FSTAT:
			dirfd = curr.GetArg(0).GetFd()
			path = ""
		case unix.SYS_NEWFSTATAT:
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
		case unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2:
			dirfd = curr.GetArg(0).GetFd()
			path = curr.GetArg(1).GetPath()
			dirfd2 = curr.GetArg(2).GetFd()
			path2 = curr.GetArg(3).GetPath()
		}
		goto CHECK_WRITEABLE_2

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

	// passthrough
	case unix.SYS_CLOSE:
		goto PASSTHROUGH

	//
	default:
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

PASSTHROUGH:
	e.logger.Info("syscall: Enter:   => fsfiter: PASSTHROUGH")
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenExit(curr *ptrace.Syscall, prev *ptrace.Syscall) (error, error) {
	// prepare data from regs
	var retval = curr.GetRetval()
	if err := retval.Read(); err != nil {
		return nil, fmt.Errorf("ptrace: %s", err.Error())
	}

	// logging
	e.logger.Info(fmt.Sprintf("syscall: Exit_:   => retval: %s", retval))

	// track fd
	r1, err := e.applySyscallFilterWhenExit_TraceFd(curr, prev)
	if err != nil || r1 != nil {
		return r1, err
	}

	// ok
	return nil, nil
}

func (e *Executor) applySyscallFilterWhenExit_TraceFd(curr *ptrace.Syscall, prev *ptrace.Syscall) (error, error) {
	var retval = curr.GetRetval()
	if retval.HasError() {
		return nil, nil
	}

	var dirfd int
	var path string
	var nr = curr.GetNR()
	switch nr {
	case unix.SYS_OPEN, unix.SYS_OPENAT, unix.SYS_CREAT:
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
		if err := e.fsfilter.TraceFd(retval.GetValue(), path, dirfd); err != nil {
			return nil, fmt.Errorf("ptrace: %s", err.Error())
		}
	}

	return nil, nil
}
