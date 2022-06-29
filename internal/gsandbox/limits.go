package gsandbox

type Limits struct {
	RlimitAS     *uint64 `json:"as,omitempty"`     // the maximum size of virtual memory (address space) in bytes
	RlimitCORE   *uint64 `json:"core,omitempty"`   // the maximum size of core files created
	RlimitCPU    *uint64 `json:"cpu,omitempty"`    // the maximum amount of cpu time in seconds
	RlimitFSIZE  *uint64 `json:"fsize,omitempty"`  // the maximum size of files written by the shell and its children
	RlimitNOFILE *uint64 `json:"nofile,omitempty"` // the maximum number of open file descriptors
}
