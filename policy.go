package gsandbox

type Policy struct {
	ShareNetwork    string           `yaml:"share-net"`
	InheritEnv      string           `yaml:"env"`
	Limits          PolicyLimits     `yaml:"limits"`
	AllowedSyscalls []string         `yaml:"syscalls"`
	FileSystem      PolicyFileSystem `yaml:"fs"`
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
