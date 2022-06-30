package gsandbox

type Policy struct {
	Limits          `yaml:"limits"`
	AllowedSyscalls []string `yaml:"syscalls"`
}
