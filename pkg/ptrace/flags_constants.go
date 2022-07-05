package ptrace

import (
	"golang.org/x/sys/unix"
)

type FlagOpenConstant int
type FlagFcntlCmdConstant int

// https://man7.org/linux/man-pages/man2/open.2.html
//go:generate stringer -type=FlagOpenConstant -output=flags_constants_open_string.go
const (
	O_APPEND   FlagOpenConstant = unix.O_APPEND
	O_ASYNC    FlagOpenConstant = unix.O_ASYNC
	O_CLOEXEC  FlagOpenConstant = unix.O_CLOEXEC
	O_CREAT    FlagOpenConstant = unix.O_CREAT
	O_DIRECT   FlagOpenConstant = unix.O_DIRECT
	O_DSYNC    FlagOpenConstant = unix.O_DSYNC
	O_EXCL     FlagOpenConstant = unix.O_EXCL
	O_NOATIME  FlagOpenConstant = unix.O_NOATIME
	O_NOCTTY   FlagOpenConstant = unix.O_NOCTTY
	O_NONBLOCK FlagOpenConstant = unix.O_NONBLOCK
	O_PATH     FlagOpenConstant = unix.O_PATH
	O_SYNC     FlagOpenConstant = unix.O_SYNC
	O_TMPFILE  FlagOpenConstant = unix.O_TMPFILE
	O_TRUNC    FlagOpenConstant = unix.O_TRUNC
	O_RDONLY   FlagOpenConstant = unix.O_RDONLY
	O_WRONLY   FlagOpenConstant = unix.O_WRONLY
	O_RDWR     FlagOpenConstant = unix.O_RDWR
)

// https://man7.org/linux/man-pages/man3/fcntl.3p.html
//go:generate stringer -type=FlagFcntlCmdConstant -output=flags_constants_fcntl_cmd_string.go
const (
	F_DUPFD         FlagFcntlCmdConstant = unix.F_DUPFD
	F_GETFD         FlagFcntlCmdConstant = unix.F_GETFD
	F_SETFD         FlagFcntlCmdConstant = unix.F_SETFD
	F_GETFL         FlagFcntlCmdConstant = unix.F_GETFL
	F_SETFL         FlagFcntlCmdConstant = unix.F_SETFL
	F_GETLK         FlagFcntlCmdConstant = unix.F_GETLK
	F_SETLK         FlagFcntlCmdConstant = unix.F_SETLK
	F_SETLKW        FlagFcntlCmdConstant = unix.F_SETLKW
	F_SETOWN        FlagFcntlCmdConstant = unix.F_SETOWN
	F_GETOWN        FlagFcntlCmdConstant = unix.F_GETOWN
	F_SETSIG        FlagFcntlCmdConstant = unix.F_SETSIG
	F_GETSIG        FlagFcntlCmdConstant = unix.F_GETSIG
	F_SETOWN_EX     FlagFcntlCmdConstant = unix.F_SETOWN_EX
	F_GETOWN_EX     FlagFcntlCmdConstant = unix.F_GETOWN_EX
	F_DUPFD_CLOEXEC FlagFcntlCmdConstant = unix.F_DUPFD_CLOEXEC
	F_SETPIPE_SZ    FlagFcntlCmdConstant = unix.F_SETPIPE_SZ
	F_GETPIPE_SZ    FlagFcntlCmdConstant = unix.F_GETPIPE_SZ
)
