package gsandbox

type Limits struct {
	RlimitAS     *uint64 `yaml:"as,omitempty"`
	RlimitCORE   *uint64 `yaml:"core,omitempty"`
	RlimitCPU    *uint64 `yaml:"cpu,omitempty"`
	RlimitFSIZE  *uint64 `yaml:"fsize,omitempty"`
	RlimitNOFILE *uint64 `yaml:"nofile,omitempty"`
}
