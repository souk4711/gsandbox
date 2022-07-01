package gsandbox

type Policy struct {
	ShareNetwork    string           `yaml:"share-net"`
	Limits          PolicyLimits     `yaml:"limits"`
	AllowedSyscalls []string         `yaml:"syscalls"`
	FileSystem      PolicyFileSystem `yaml:"fs"`
}

type PolicyLimits struct {
	AS     string `yaml:"as,omitempty"`
	CORE   string `yaml:"core,omitempty"`
	CPU    string `yaml:"cpu,omitempty"`
	FSIZE  string `yaml:"fsize,omitempty"`
	NOFILE string `yaml:"nofile,omitempty"`
}

type PolicyFileSystem struct {
	ReadableFlist []string `yaml:"rd-flist"`
	WritableFlist []string `yaml:"wr-flist"`
}
