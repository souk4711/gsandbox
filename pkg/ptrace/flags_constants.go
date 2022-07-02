// Ref: https://github.com/google/gvisor/blob/master/pkg/abi/linux/file.go

package ptrace

type FlagOpenConstant int

// Constants for open(2).
//go:generate stringer -type=FlagOpenConstant -output=flags_constants_string_open.go
const (
	O_ACCMODE  FlagOpenConstant = 000000003
	O_RDONLY   FlagOpenConstant = 000000000
	O_WRONLY   FlagOpenConstant = 000000001
	O_RDWR     FlagOpenConstant = 000000002
	O_CREAT    FlagOpenConstant = 000000100
	O_EXCL     FlagOpenConstant = 000000200
	O_NOCTTY   FlagOpenConstant = 000000400
	O_TRUNC    FlagOpenConstant = 000001000
	O_APPEND   FlagOpenConstant = 000002000
	O_NONBLOCK FlagOpenConstant = 000004000
	O_DSYNC    FlagOpenConstant = 000010000
	O_ASYNC    FlagOpenConstant = 000020000
	O_NOATIME  FlagOpenConstant = 001000000
	O_CLOEXEC  FlagOpenConstant = 002000000
	O_SYNC     FlagOpenConstant = 004000000 // __O_SYNC in Linux
	O_PATH     FlagOpenConstant = 010000000
	O_TMPFILE  FlagOpenConstant = 020000000 // __O_TMPFILE in Linux
)
