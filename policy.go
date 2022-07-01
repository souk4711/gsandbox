package gsandbox

type Policy struct {
	ShareNetwork    string `yaml:"share-net"`
	Limits          `yaml:"limits"`
	AllowedSyscalls []string `yaml:"syscalls"`
}
