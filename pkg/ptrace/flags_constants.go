package ptrace

import (
	"golang.org/x/sys/unix"
)

type FlagOpenConstant int

// https://man7.org/linux/man-pages/man2/open.2.html
//go:generate stringer -type=FlagOpenConstant -output=flags_constants_open_string.go
const (
	O_RDONLY   FlagOpenConstant = unix.O_RDONLY
	O_WRONLY   FlagOpenConstant = unix.O_WRONLY
	O_RDWR     FlagOpenConstant = unix.O_RDWR
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
)
