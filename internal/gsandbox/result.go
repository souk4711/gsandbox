package gsandbox

import (
	"fmt"
	"time"
)

const (
	resultInfoStringFormat = "" +
		"Status:       %s\n" +
		"Reason:       %s\n" +
		"Exit Code:    %d\n" +
		"Start Time:   %s\n" +
		"Finsih Time:  %s\n" +
		"Real Time:    %s\n" +
		"System Time:  %s\n" +
		"User Time:    %s\n" +
		"Max RSS:      %dkb\n"
)

type Result struct {
	Status
	Reason string // more details about the status

	ExitCode   int           // exit code or signal number that caused an exit
	StartTime  time.Time     // when process started
	FinishTime time.Time     // when process finished
	RealTime   time.Duration // wall time used
	SystemTime time.Duration // system CPU time used
	UserTime   time.Duration // user CPU time used
	Maxrss     int64         // maximum resident set size (in kilobytes)
}

func (r *Result) Info() string {
	var startTime = ""
	if !r.StartTime.IsZero() {
		startTime = r.StartTime.Format(time.ANSIC)
	}

	var finishTime = ""
	if !r.FinishTime.IsZero() {
		finishTime = r.FinishTime.Format(time.ANSIC)
	}

	return fmt.Sprintf(
		resultInfoStringFormat,
		r.Status,
		r.Reason,
		r.ExitCode,
		startTime,
		finishTime,
		r.RealTime,
		r.SystemTime,
		r.UserTime,
		r.Maxrss,
	)
}
