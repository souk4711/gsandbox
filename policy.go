package gsandbox

type Policy struct {
	InheritEnv       string           `yaml:"env"`
	ShareNetwork     string           `yaml:"share-net"`
	WorkingDirectory string           `yaml:"work-dir"`
	Limits           PolicyLimits     `yaml:"limits"`
	AllowedSyscalls  []string         `yaml:"syscalls"`
	FileSystem       PolicyFileSystem `yaml:"fs"`
}

type PolicyLimits struct {
	AS        string `yaml:"as,omitempty"`
	CORE      string `yaml:"core,omitempty"`
	CPU       string `yaml:"cpu,omitempty"`
	FSIZE     string `yaml:"fsize,omitempty"`
	NOFILE    string `yaml:"nofile,omitempty"`
	WALLCLOCK string `yaml:"wallclock,omitempty"`
}

type PolicyFileSystem struct {
	ReadableFiles   []string `yaml:"rd-files"`
	WritableFiles   []string `yaml:"wr-files"`
	ExecutableFiles []string `yaml:"ex-files"`
}
