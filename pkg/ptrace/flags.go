package ptrace

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type Fd int
type FlagOpen int
type FlagFcntlCmd int

func (fd Fd) String() string {
	switch int(fd) {
	case unix.AT_FDCWD:
		return "AT_FDCWD"
	case unix.Stdin:
		return "STDIN"
	case unix.Stdout:
		return "STDOUT"
	case unix.Stderr:
		return "STDERR"
	default:
		return fmt.Sprint(int(fd))
	}
}

func (f FlagOpen) String() string {
	var currFlag = int(f)
	var str = ""
	var update = func(testFlag int) {
		if currFlag&testFlag != 0 {
			str += FlagOpenStringer(testFlag).String() + "|"
		}
		currFlag = currFlag &^ int(testFlag)
	}

	update(unix.O_APPEND)
	update(unix.O_ASYNC)
	update(unix.O_CLOEXEC)
	update(unix.O_CREAT)
	update(unix.O_DIRECT)
	update(unix.O_DSYNC)
	update(unix.O_EXCL)
	update(unix.O_NOATIME)
	update(unix.O_NOCTTY)
	update(unix.O_NONBLOCK)
	update(unix.O_PATH)
	update(unix.O_SYNC)
	update(unix.O_TMPFILE)
	update(unix.O_TRUNC)

	switch currFlag {
	case unix.O_RDONLY:
		str += "O_RDONLY"
	case unix.O_WRONLY:
		str += "O_WRONLY"
	case unix.O_RDWR:
		str += "O_RDWR"
	}

	return str
}

func (f FlagFcntlCmd) String() string {
	return FlagFcntlCmdStringer(int(f)).String()
}
