package ptrace

import (
	"golang.org/x/sys/unix"
)

type FlagOpenStringer int
type FlagFcntlCmdStringer int

// https://man7.org/linux/man-pages/man2/open.2.html
//go:generate stringer -type=FlagOpenStringer -output=flags_stringer_open_string.go
const (
	O_APPEND   FlagOpenStringer = unix.O_APPEND
	O_ASYNC    FlagOpenStringer = unix.O_ASYNC
	O_CLOEXEC  FlagOpenStringer = unix.O_CLOEXEC
	O_CREAT    FlagOpenStringer = unix.O_CREAT
	O_DIRECT   FlagOpenStringer = unix.O_DIRECT
	O_DSYNC    FlagOpenStringer = unix.O_DSYNC
	O_EXCL     FlagOpenStringer = unix.O_EXCL
	O_NOATIME  FlagOpenStringer = unix.O_NOATIME
	O_NOCTTY   FlagOpenStringer = unix.O_NOCTTY
	O_NONBLOCK FlagOpenStringer = unix.O_NONBLOCK
	O_PATH     FlagOpenStringer = unix.O_PATH
	O_SYNC     FlagOpenStringer = unix.O_SYNC
	O_TMPFILE  FlagOpenStringer = unix.O_TMPFILE
	O_TRUNC    FlagOpenStringer = unix.O_TRUNC
	O_RDONLY   FlagOpenStringer = unix.O_RDONLY
	O_WRONLY   FlagOpenStringer = unix.O_WRONLY
	O_RDWR     FlagOpenStringer = unix.O_RDWR
)

// https://man7.org/linux/man-pages/man3/fcntl.3p.html
//go:generate stringer -type=FlagFcntlCmdStringer -output=flags_stringer_fcntl_cmd_string.go
const (
	F_DUPFD         FlagFcntlCmdStringer = unix.F_DUPFD
	F_GETFD         FlagFcntlCmdStringer = unix.F_GETFD
	F_SETFD         FlagFcntlCmdStringer = unix.F_SETFD
	F_GETFL         FlagFcntlCmdStringer = unix.F_GETFL
	F_SETFL         FlagFcntlCmdStringer = unix.F_SETFL
	F_GETLK         FlagFcntlCmdStringer = unix.F_GETLK
	F_SETLK         FlagFcntlCmdStringer = unix.F_SETLK
	F_SETLKW        FlagFcntlCmdStringer = unix.F_SETLKW
	F_SETOWN        FlagFcntlCmdStringer = unix.F_SETOWN
	F_GETOWN        FlagFcntlCmdStringer = unix.F_GETOWN
	F_SETSIG        FlagFcntlCmdStringer = unix.F_SETSIG
	F_GETSIG        FlagFcntlCmdStringer = unix.F_GETSIG
	F_SETOWN_EX     FlagFcntlCmdStringer = unix.F_SETOWN_EX
	F_GETOWN_EX     FlagFcntlCmdStringer = unix.F_GETOWN_EX
	F_DUPFD_CLOEXEC FlagFcntlCmdStringer = unix.F_DUPFD_CLOEXEC
	F_SETPIPE_SZ    FlagFcntlCmdStringer = unix.F_SETPIPE_SZ
	F_GETPIPE_SZ    FlagFcntlCmdStringer = unix.F_GETPIPE_SZ
)
