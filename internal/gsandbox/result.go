package gsandbox

import (
	"time"
)

type Result struct {
	Status     `json:"status"`
	Reason     string        `json:"reason"`     // more details about the status
	ExitCode   int           `json:"exitCode"`   // exit code or signal number that caused an exit
	StartTime  time.Time     `json:"startTime"`  // when process started
	FinishTime time.Time     `json:"finishTime"` // when process finished
	RealTime   time.Duration `json:"realTime"`   // wall time used
	SystemTime time.Duration `json:"systemTime"` // system CPU time used
	UserTime   time.Duration `json:"userTime"`   // user CPU time used
	Maxrss     int64         `json:"maxrss"`     // maximum resident set size (in kilobytes)
}
