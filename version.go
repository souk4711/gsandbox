package gsandbox

import (
	"fmt"
	"runtime"
	"time"
)

const (
	versionName             = "Gsandbox"
	versionNumber           = "0.0.1"
	versionInfoStringFormat = "" +
		"Name:        %s\n" +
		"Version:     %s\n" +
		"Go Version:  %s\n" +
		"Git Commit:  %s\n" +
		"Built:       %s\n" +
		"OS/Arch:     %s/%s\n"
)

var (
	version = &Version{
		Name:      versionName,
		Number:    versionNumber,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		ARCH:      runtime.GOARCH,
	}
)

type Version struct {
	Name      string
	Number    string
	GoVersion string
	GitCommit string
	BuiltTime int64
	OS        string
	ARCH      string
}

func (v *Version) Info() string {
	var built = ""
	if v.BuiltTime != 0 {
		built = time.Unix(v.BuiltTime, 0).Format(time.ANSIC)
	}

	return fmt.Sprintf(
		versionInfoStringFormat,
		v.Name,
		v.Number,
		v.GoVersion,
		v.GitCommit,
		built,
		v.OS, v.ARCH,
	)
}

func GetVersion() *Version {
	return version
}
