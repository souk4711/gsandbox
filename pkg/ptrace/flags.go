package ptrace

import (
	"fmt"

	"golang.org/x/sys/unix"
)

type Fd int
type FlagOpen int

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
	var str = ""
	var update = func(flag FlagOpenConstant) {
		if int(f) == int(flag) || int(f)&int(flag) != 0 {
			str += flag.String() + "|"
		}
	}

	update(O_RDONLY)
	update(O_WRONLY)
	update(O_RDWR)

	update(O_APPEND)
	update(O_ASYNC)
	update(O_CLOEXEC)
	update(O_CREAT)
	update(O_DIRECT)
	update(O_DSYNC)
	update(O_EXCL)
	update(O_NOATIME)
	update(O_NOCTTY)
	update(O_NONBLOCK)
	update(O_PATH)
	update(O_SYNC)
	update(O_TMPFILE)
	update(O_TRUNC)

	if str == "" {
		return fmt.Sprint(int(f))
	} else {
		return str[:len(str)-1]
	}
}
