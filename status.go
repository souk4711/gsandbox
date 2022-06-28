package gsandbox

type Status int

//go:generate stringer -type=Status -linecomment
const (
	StatusUnset               Status = iota // unset
	StatusOK                                // ok
	StatusTimeLimitExceeded                 // time limit execeeded
	StatusMemoryLimitExceeded               // memory limit exceeded
	StatusOutputLimitExceeded               // output limit exceeded
	StatusViolation                         // syscall violation
	StatusSignaled                          // terminated with a signal
	StatusExitFailure                       // exit with nonzero code
)
