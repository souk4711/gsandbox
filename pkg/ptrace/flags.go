package ptrace

import "fmt"

type FlagOpen int

func (f FlagOpen) String() string {
	var str = ""
	var update = func(flag FlagOpenConstant) {
		if int(f)&int(flag) != 0 {
			str += flag.String() + "|"
		}
	}

	update(O_ACCMODE)
	update(O_RDONLY)
	update(O_WRONLY)
	update(O_RDWR)
	update(O_CREAT)
	update(O_EXCL)
	update(O_NOCTTY)
	update(O_TRUNC)
	update(O_APPEND)
	update(O_NONBLOCK)
	update(O_DSYNC)
	update(O_ASYNC)
	update(O_NOATIME)
	update(O_CLOEXEC)
	update(O_SYNC)
	update(O_PATH)
	update(O_TMPFILE)

	if str == "" {
		return fmt.Sprint(int(f))
	} else {
		return str[:len(str)-1]
	}
}
